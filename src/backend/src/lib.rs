#![feature(libc)]

// NOTE: I apologize for the many different zeroization classes in here
// TODO: zeroization structs need to be cleaned to the point of only using one or two (e.g. remove Secret class and only use zeroization features)
// TODO: code needs refactoring
// TODO: refactor so some functions return Result when panic instead of crashing app
use std::fs::{File, create_dir_all};
use std::path::Path;
use std::io::{Write, Read};
use std::sync::{mpsc, Arc};
use std::sync::mpsc::*;

use std::thread;
use chbs::{config::BasicConfig, prelude::*}; 
use serde::{Serialize, Deserialize};  
use secrecy::{Zeroize};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::*;
use sodiumoxide::crypto::kdf;
use sodiumoxide::crypto::kdf::blake2b::derive_from_key;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::sha256;

use jni::{JNIEnv};
use jni::descriptors::Desc;
use jni::sys::{jclass, jobject, jlong, jint, jstring, jchar, jcharArray, jboolean, jobjectArray};
use jni::objects::{JObject,JString,JClass};

#[cfg(feature = "zeroize_derive")]
use zeroize::{Zeroize, ZeroizeOnDrop};

static MASTERKY_CONTEXT: [u8; 8]   = *b"MASTERKY"; 

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct MiscVaultData {
    id:       Option<i64>,
    username: Option<String>,
    email:    Option<String>, 
    password: Option<String>,
    otp:      Option<String>,
    website:  Option<String>,
    image:    Option<String>, 
    note:     Option<String>, 
    message:  String // used for commands when communicating to vault thread
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct VaultFolderData { 
    folderName: String,
    idRefs: Vec<i64>
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct VaultSettings { 
    kdfRepetitions: u64, 
    createBackup:   Option<String>, 
    maxBackups:     Option<u8>, 
    theme:          Option<String>
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct VaultFormat { 
    accountList: Vec<MiscVaultData>,
    folderList:  Vec<VaultFolderData>,
    signature:   Option<String>
}

#[derive(Serialize, Deserialize)]
struct VaultFileFormat {
    vault: Vec<u8>,
    settings: VaultSettings, 
    nonce: [u8; 24]
}

#[derive(Serialize, Deserialize)]
struct RecoveryFileFormat { 
    recovery: Vec<u8>, 
    nonce: [u8; 24]
}

type VaultCommunicationPtr = *mut (Sender<Option<MiscVaultData>>, Receiver<Option<MiscVaultData>>);

// generates recovery code
fn generateRecoveryCode() -> (secretbox::Key, String) {

    // configure dicewear
    let mut config = BasicConfig::default(); 
    config.words = 24; 
    let scheme = config.to_scheme(); 

    // generate a recovery code
    let recoveryRaw = scheme.generate();

    // compress the recovery code via sha256
    let recoveryCode = secretbox::Key(
        sha256::hash(recoveryRaw.as_bytes()).0
    );
    
    
    // derive the recovery code 600000 times to get final code
    let CONTEXT: [u8; 8]   = *b"RECOVERY"; 
    let mut subkey = secretbox::Key([0; secretbox::KEYBYTES]);
    
    derive_from_key(&mut subkey.0[..], 1, CONTEXT, &(kdf::Key::from_slice(&recoveryCode.0).unwrap()));
    for n in 2..600000 {
        let old_subkey = kdf::Key::from_slice(&subkey.0).unwrap(); 
        derive_from_key(&mut subkey.0[..], n, CONTEXT, &old_subkey);
    }

    return (recoveryCode, recoveryRaw); 
}

// TODO: backup when open (if option is specified)
// dissasembles Vault File, decrypts, and turns it into a memory vault
// TODO: Return Result<VaultFormat, Err> later
fn dissasembleVaultFile(name: &str, password: &str) -> (VaultFormat, VaultFileFormat) { 
    let vaultDir = format!("{}/.vaults/{}", dirs::home_dir()
        .unwrap()
        .as_path()
        .to_str()
        .unwrap()
    , name);

    let mut vaultFile             = File::open(vaultDir.clone()+"/vdata/data.uvault").unwrap();
    let mut vaultFileContents     = Vec::new();
    
    vaultFile.read_to_end(&mut vaultFileContents).unwrap();

    let mut file: VaultFileFormat = bincode::deserialize(&vaultFileContents[..]).unwrap();
    let mut extractedNonce        = Nonce::from_slice(&file.nonce).unwrap(); 
    
    
    let localPassword = secretbox::Key(
        sha256::hash(password.as_bytes()).0
    );

    let mut subkey = secretbox::Key([0; secretbox::KEYBYTES]);

    derive_from_key(&mut subkey.0[..], 1, MASTERKY_CONTEXT, &(kdf::Key::from_slice(&localPassword.0).unwrap()));
    for n in 2..file.settings.kdfRepetitions {
        let old_subkey = kdf::Key::from_slice(&subkey.0).unwrap(); 
        derive_from_key(&mut subkey.0[..], n, MASTERKY_CONTEXT, &old_subkey);
    }

    // decrypt vault binary and deserialize it
    let mut dissasembledVault: VaultFormat = bincode::deserialize(
        open(&(file.vault), None, &extractedNonce, &Key::from_slice(&subkey.0).unwrap()).unwrap().as_slice()
    ).unwrap();
   
    
    return (dissasembledVault, file) ;


}

// test if the vault path is already Initialized
// TODO: error handling
#[no_mangle]
pub extern "system" fn Java_org_undefined_uvault_UVaultMain_vaultPathExists(env: JNIEnv, _obj: jclass) -> jboolean { 
    let allVaultDir = format!("{}/.vaults/", dirs::home_dir()
    .unwrap()
    .as_path()
    .to_str()
    .unwrap());

    if Path::new(allVaultDir.as_str()).is_dir() { 
        return true as u8;
    }
    return false as u8; 
}

// meant to be executed after "vaultPathExists"
// Doesn't need zeroization (no confidential info)
// TODO: Error handling
#[no_mangle]
pub extern "system" fn Java_org_undefined_uvault_UVaultMain_fetchVaults(env: JNIEnv, _obj: jclass) -> jobjectArray {
    let allVaultDir = format!("{}/.vaults/", dirs::home_dir()
        .unwrap()
        .as_path()
        .to_str()
        .unwrap()
    );

    let mut vaults = std::fs::read_dir(allVaultDir.clone()).unwrap(); 
    let retArr  = env.new_object_array(
        vaults.count().try_into().unwrap(), 
        env.find_class("java/lang/String").unwrap(), 
        env.new_string("").unwrap()
    ).expect("[BACKEND/ERR]: Failed to create object array for vault list."); 

    // .count consumes the ReadDir, so we have to recreate it to avoid ownership errors
    vaults = std::fs::read_dir(allVaultDir.clone()).unwrap();
    let mut i = 0;

    // TODO: Access history & other values
    for vault in vaults  {
        env.set_object_array_element(retArr, i, env.new_string(vault.unwrap().path().into_os_string().into_string().unwrap()).unwrap());
        i+=1; 
    }
    
    return retArr;
}

// TODO: add error return codes, make better error handling
#[no_mangle]
pub extern "system" fn Java_org_undefined_uvault_UVaultMain_generateNewVault(env: JNIEnv, _obj: jclass, name:  JString, password:  jcharArray, passwordLength: jlong) -> jint {
    sodiumoxide::init();


    let mut passwordBuf: Vec<u16> =  Vec::with_capacity(passwordLength as usize);
    env.get_char_array_region(password, 0, &mut passwordBuf);
    passwordBuf.zeroize(); 
    // java-side password buff will have to stay a little longer
    // TODO: zeroize java-side here

    let mut convertedName: String = env.get_string(name.into()).unwrap().into();
    let mut convertedPassword: String = String::from_utf16(passwordBuf.as_slice()).unwrap();

    let vaultDir = format!("{}/.vaults/{}", dirs::home_dir()
        .unwrap()
        .as_path()
        .to_str()
        .unwrap()
        , convertedName);

    // if path already exists, discontinue the operation
    if Path::new(vaultDir.as_str()).is_dir() { 
        println!("[BACKEND]: Vault already exists.");
        env.throw("ERR: Vault already exists");

        // TODO: error handling
        return -1; 
    }

    create_dir_all(vaultDir.clone());
    create_dir_all(vaultDir.clone()+"/vdata/");

    //println!("{:?}", password);
    let mut vault: VaultFormat = VaultFormat {
        accountList: Vec::new(),
        folderList: Vec::new(),
        signature: None
    };

    // serialize vault for file writing
    let mut bin = bincode::serialize(&vault).unwrap();

    // generate a new recovery code returns: (key derived, raw)
    // recovery code is only for transferal between devices
    // on the local device, user password is used to encrypt for efficiency
    let mut recoveryCode = generateRecoveryCode(); 

    // use local password to encrypt recovery key for use in syncing
    let localPassword = secretbox::Key(
        sha256::hash(convertedPassword.as_bytes()).0
    );

    // derive the master password 600000 times to get final code
   
    let mut subkey = secretbox::Key([0; secretbox::KEYBYTES]);

    derive_from_key(&mut subkey.0[..], 1, MASTERKY_CONTEXT, &(kdf::Key::from_slice(&localPassword.0).unwrap()));
    for n in 2..600000 {
        let mut old_subkey = kdf::Key::from_slice(&subkey.0).unwrap(); 
        derive_from_key(&mut subkey.0[..], n, MASTERKY_CONTEXT, &old_subkey);
        old_subkey.0.zeroize();
    }

    let recoveryNonce = gen_nonce(); 
    // used in a seperate file
    let encryptedRecoveryData = seal(recoveryCode.1.as_bytes(), None, &recoveryNonce, &Key::from_slice(&subkey.0).unwrap());
    // genarate nonce

    let vaultNonce = gen_nonce(); 
    // encrypt message
    let vaultData = seal(bin.as_slice(), None, &vaultNonce, &Key::from_slice(&subkey.0).unwrap());


    // adds the nonce to the file
    let mut finalVaultOutputData = bincode::serialize(&VaultFileFormat {
        vault:     vaultData,
        settings:   VaultSettings { 
            kdfRepetitions: 600000, 
            createBackup:   Some("open".to_string()),
            maxBackups:     Some(7),
            theme:          None
        },
        nonce:     vaultNonce.0
     }).unwrap();

    let  mut finalRecoveryOutputData = bincode::serialize(&RecoveryFileFormat {
        recovery: encryptedRecoveryData, 
        nonce:    recoveryNonce.0
    }).unwrap();



    let mut vaultFile        = File::create(vaultDir.clone()+"/vdata/data.uvault").unwrap();
    let mut recoveryCodeFile = File::create(vaultDir.clone()+"/key.uvrkey").unwrap();
    vaultFile.write_all(finalVaultOutputData.as_slice());
    recoveryCodeFile.write_all(finalRecoveryOutputData.as_slice());
    
    // zeroize what can be zeroized manually
    convertedName.zeroize();
    convertedPassword.zeroize();
    finalVaultOutputData.zeroize();
    finalRecoveryOutputData.zeroize(); 
    vault.zeroize();
    recoveryCode.1.zeroize();

    bin.zeroize();

    // TODO: error handling
    // recovery code zer
    return 0; 
    //vault.accountList.zeroize();
    //vault.signature.zeroize();
    
}


// TODO: make more secure by passing vault to frontend instaid of a Sender/Receiver pointer
// OR: leave it as it is but ensure no possible memory leaks, race conditions, etc.
// thread communication shouldn't be High-risk since it can't really affect the vault (just make sure to zeroize/erase last value in heap)
#[no_mangle]
pub unsafe extern "system" fn Java_org_undefined_uvault_UVaultMain_openVault(_env: JNIEnv, _obj: jclass, name: JString, password: JString) -> jlong {
    // TODO: refactor/rename variables
    let binding = Arc::new(mpsc::channel::<Option<MiscVaultData>>());
    let rawtcp = Arc::into_raw(binding) as usize;
    let cp = rawtcp as VaultCommunicationPtr;
    let mut convertedName: String = _env.get_string(name.into()).unwrap().into();
    let mut convertedPassword: String = _env.get_string(password.into()).unwrap().into();

     thread::spawn(move || {
        let cp =  rawtcp as VaultCommunicationPtr;
        
        let (mut memoryVault, mut fileFormat) = dissasembleVaultFile(convertedName.as_str(), convertedPassword.as_str()); 
        
        // erase password from memory after use (java gc will take care of the java-side)
        convertedPassword.zeroize();
        std::mem::drop(convertedPassword);

        loop {

            if cp.is_null() {
              println!("[BACKEND/FATALERROR]: Vault communication memory is corrupted, pointer returned null");
              break;
            };

            let val = (*cp).1.recv().unwrap();

            // None is the vault terminator (closes vault and erases it from memory)
            if val.is_none() {
                println!("[BACKEND]: Sucessfully closed vault communications.");
                break;
            } else {

                let miscVaultData: MiscVaultData = val.unwrap(); 
                let vaultOp: &str = &miscVaultData.message as &str;
                match vaultOp {
                    "fetch account" => {
                        
                    },
                    "new account"   => {
                        
                    },
                    "delete account" => { 

                    }, 
                    "fetch headers" => { 

                    }, 
                    _ => ()
                }
            }
        }

        // free and destruct memory from box
        {
          Arc::from_raw(cp);
        }

    });

    if cp.is_null() {
       println!("[BACKEND/FATALERROR]: Vault communication memory is corrupted, pointer returned null.");
       return -1;
    };

    // WARNING: unsafe, used to communicate to the vault
    return rawtcp as jlong;
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_undefined_uvault_UVaultMain_closeVault(_env: &mut JNIEnv, _obj: jclass, addr: jlong) -> jint {
    let cp = addr as VaultCommunicationPtr;
    if cp.is_null() {
           println!("[BACKEND/FATALERROR]: Vault communication memory is corrupted, pointer returned null.");
           return -1;
    };
    (*cp).0.send(None);
    return 0;
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_undefined_uvault_UVaultMain_fetchAllMiscVaultDataHeaders(_env: &mut JNIEnv, _obj: jclass, addr: jlong) -> jobject { 
    let cp = addr as VaultCommunicationPtr;
    if cp.is_null() {
        println!("[BACKEND/FATALERROR]: Vault communication memory is corrupted, pointer returned null.");
        return *JObject::null();
    };

    (*cp).0.send(Some(
        MiscVaultData { 
            id:       None,
            username: None,
            email:    None, 
            password: None,
            otp:      None,
            website:  None,
            image:    None, 
            note:     None, 
            message:  "fetch headers".to_string()
        }
    )).unwrap(); 

    return *JObject::null(); 
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memoryVaultCreation() {
        println!("Starting test...");
        unsafe {
        let x = Java_org_undefined_uvault_UVaultMain_openVault();

        Java_org_undefined_uvault_UVaultMain_closeVault(x);
        }
    }
}
