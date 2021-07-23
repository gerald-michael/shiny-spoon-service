use crate::crypt;
use crypto::digest::Digest;
use crypto::*;
use itertools::Itertools;
use neon::prelude::*;
use std::cell::RefCell;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
// use std::time::Instant;
const ALGORITHMS: [&str; 16] = [
    "sha1",
    "sha256",
    "sha512",
    "sha384",
    "md5_linux",
    "whirlpool",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHAKE128",
    "SHAKE256",
    "Keccak224",
    "Keccak256",
    "Keccak384",
    "Keccak512",
];
type BoxedCracker = JsBox<RefCell<Cracker>>;
pub struct Cracker {
    hash: String,
    threads: u8,
    salt: String,
    counter: Arc<AtomicIsize>,
    terminate: Arc<AtomicBool>,
    callback: Root<JsFunction>,
    shutdown: Option<Root<JsFunction>>,
    queue: Arc<EventQueue>,
}

impl Cracker {
    fn find_password_sha1(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha1::Sha1::new();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_sha512(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha2::Sha512::new();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_sha256(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha2::Sha256::new();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_sha384(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha2::Sha384::new();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_md5_linux(
        passwords: Vec<String>,
        hash: String,
        salt: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            if hash == crypt::md5(&password, &salt) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_whirlpool(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = whirlpool::Whirlpool::new();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_sha3_224(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::sha3_224();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_sha3_256(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::sha3_256();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_sha3_384(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::sha3_384();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_sha3_512(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::sha3_512();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_shake128(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::shake_128();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_shake256(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::shake_256();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_keccak224(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::keccak224();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_keccak256(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::keccak256();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_keccak384(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::keccak384();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn find_password_keccak512(
        passwords: Vec<String>,
        hash: String,
        sender: mpsc::Sender<String>,
        counter: Arc<AtomicIsize>,
        terminate: Arc<AtomicBool>,
    ) {
        let mut iterations = 0;
        for password in passwords {
            let mut hasher = sha3::Sha3::keccak512();
            hasher.input_str(&password);
            if hash == hasher.result_str() {
                counter.fetch_add(iterations, Ordering::Relaxed);
                terminate.store(true, Ordering::Relaxed);
                match sender.send(password) {
                    Ok(_) => break,
                    Err(_) => panic!("Receiver stopped listening!"),
                }
            }
            if terminate.load(Ordering::Relaxed) {
                counter.fetch_add(iterations, Ordering::Relaxed);
                break;
            }
            iterations += 1;
        }
    }
    fn cracker_crack_using_password_file<'a, C: Context<'a>>(
        &self,
        mut cx: C,
        algorithm: &str,
        file_path: &str,
        buff_size: u64,
    ) -> JsResult<'a, JsUndefined> {
        if !ALGORITHMS.contains(&algorithm) {
            let callback = self.callback.clone(&mut cx);
            let callback = callback.into_inner(&mut cx);
            let this = cx.undefined();
            let result = JsObject::new(&mut cx);
            let message = cx.string("Incorrect algorithm");
            result.set(&mut cx, "error", message).ok();
            let args = vec![result];
            callback.call(&mut cx, this, args)?;
            return Ok(cx.undefined());
        }
        let algorithm_n = algorithm.clone().to_owned();
        let file = File::open(file_path).unwrap();
        let reader = BufReader::new(file);
        let hash = self.hash.clone();
        let terminate = self.terminate.clone();
        let salt = self.salt.clone();
        let callback = self.callback.clone(&mut cx);
        let if_callback = self.callback.clone(&mut cx);
        let queue = Arc::clone(&self.queue);
        let counter = self.counter.clone();
        let threads = self.threads.clone();
        let (sender, receiver) = mpsc::channel::<String>();
        thread::spawn(move || {
            for chunk in &reader.lines().chunks(buff_size as usize) {
                let arr: Vec<_> = chunk.collect();
                let names: Vec<String> = arr.into_iter().filter_map(|e| e.ok()).collect();
                let mut handles = vec![];
                for chunk_chunk in names.chunks(names.len() / threads as usize) {
                    let passwords = chunk_chunk.to_vec();
                    let passwords = passwords.clone();
                    let thread_hash = hash.clone();
                    let thread_salt = salt.clone();
                    let thread_sender = sender.clone();
                    let thread_counter = counter.clone();
                    let thread_terminate = terminate.clone();
                    let thread_algorithm = algorithm_n.clone().to_owned();
                    let handle = thread::spawn(move || {
                        if thread_algorithm == "sha1" {
                            Cracker::find_password_sha1(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            );
                        } else if thread_algorithm == "sha256" {
                            Cracker::find_password_sha256(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "sha512" {
                            Cracker::find_password_sha512(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "sha384" {
                            Cracker::find_password_sha384(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "md5_linux" {
                            Cracker::find_password_md5_linux(
                                passwords,
                                thread_hash,
                                thread_salt,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "whirlpool" {
                            Cracker::find_password_whirlpool(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "SHA3-224" {
                            Cracker::find_password_sha3_224(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "SHA3-256" {
                            Cracker::find_password_sha3_256(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "SHA3-384" {
                            Cracker::find_password_sha3_384(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "SHA3-512" {
                            Cracker::find_password_sha3_512(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "SHAKE128" {
                            Cracker::find_password_shake128(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "SHAKE256" {
                            Cracker::find_password_shake256(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "Keccak224" {
                            Cracker::find_password_keccak224(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "Keccak256" {
                            Cracker::find_password_keccak256(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "Keccak384" {
                            Cracker::find_password_keccak384(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        } else if thread_algorithm == "Keccak512" {
                            Cracker::find_password_keccak512(
                                passwords,
                                thread_hash,
                                thread_sender,
                                thread_counter,
                                thread_terminate,
                            )
                        }
                    });
                    handles.push(handle);
                }
                for handle in handles {
                    handle.join().unwrap();
                }
                counter.fetch_add(buff_size as isize, Ordering::Relaxed);
            }
            if terminate.load(Ordering::Relaxed) == false {
                queue.send(|mut cx| {
                    let callback = if_callback.into_inner(&mut cx);
                    let this = cx.undefined();
                    let result = JsObject::new(&mut cx);
                    let error = cx.string("password not found");
                    result.set(&mut cx, "not found", error).ok();
                    let args = vec![result];
                    callback.call(&mut cx, this, args)?;
                    Ok(())
                })
            }
            match receiver.recv() {
                Ok(status) => queue.send(|mut cx| {
                    let callback = callback.into_inner(&mut cx);
                    let this = cx.undefined();
                    let result = JsObject::new(&mut cx);
                    let success = cx.string(status);
                    result.set(&mut cx, "success", success).ok();
                    let args = vec![result];
                    callback.call(&mut cx, this, args)?;
                    Ok(())
                }),
                Err(_) => queue.send(|mut cx| {
                    let callback = callback.into_inner(&mut cx);
                    let this = cx.undefined();
                    let result = JsObject::new(&mut cx);
                    let error = cx.string("error, worker threads disconnected");
                    result.set(&mut cx, "error", error).ok();
                    let args = vec![result];
                    callback.call(&mut cx, this, args)?;
                    Ok(())
                }),
            }
        });
        Ok(cx.undefined())
    }
    fn get_counter(&self) -> u64 {
        self.counter.load(Ordering::Relaxed) as u64
    }
    fn get_salt(&self) -> String {
        self.salt.clone()
    }
    fn get_hash(&self) -> String {
        self.hash.clone()
    }
}

impl Finalize for Cracker {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        let Self {
            callback, shutdown, ..
        } = self;
        if let Some(shutdown) = shutdown {
            let shutdown = shutdown.into_inner(cx);
            let this = cx.undefined();
            let args = Vec::<Handle<JsValue>>::new();
            let _ = shutdown.call(cx, this, args);
        }

        callback.drop(cx);
    }
}
fn get_user_info(path: &str, username: &str) -> (String, String) {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    let mut hash = String::from("");
    let mut salt = String::from("");

    for line in reader.lines() {
        let content = String::from(line.unwrap());

        let first_split: Vec<&str> = content.split_terminator(':').collect();
        if first_split[0] == username {
            let second_split: Vec<&str> = first_split[1].split_terminator('$').collect();

            hash = String::from(second_split[3]);
            salt = String::from(second_split[2]);

            break;
        }
    }

    (hash, salt)
}
pub fn cracker_new(mut cx: FunctionContext) -> JsResult<BoxedCracker> {
    let hash = cx.argument::<JsString>(0)?.value(&mut cx);
    let threads = cx.argument::<JsNumber>(1)?.value(&mut cx) as u8;
    let callback = cx.argument::<JsFunction>(2)?.root(&mut cx);
    let shutdown = cx.argument_opt(3);
    let queue = cx.queue();
    let shutdown = shutdown
        .map(|v| v.downcast_or_throw::<JsFunction, _>(&mut cx))
        .transpose()?
        .map(|v| v.root(&mut cx));
    let hasher = cx.boxed(RefCell::new(Cracker {
        hash,
        callback,
        shutdown,
        threads,
        salt: "".to_owned(),
        terminate: Arc::new(AtomicBool::new(false)),
        counter: Arc::new(AtomicIsize::new(0)),
        queue: Arc::new(queue),
    }));
    Ok(hasher)
}
pub fn cracker_new_from_shadow_file(mut cx: FunctionContext) -> JsResult<BoxedCracker> {
    let shadow = cx.argument::<JsString>(0)?.value(&mut cx);
    let username = cx.argument::<JsString>(1)?.value(&mut cx);
    let threads = cx.argument::<JsNumber>(2)?.value(&mut cx) as u8;
    let callback = cx.argument::<JsFunction>(3)?.root(&mut cx);
    let shutdown = cx.argument_opt(4);
    let queue = cx.queue();
    let shutdown = shutdown
        .map(|v| v.downcast_or_throw::<JsFunction, _>(&mut cx))
        .transpose()?
        .map(|v| v.root(&mut cx));
    let (hash, salt) = get_user_info(&shadow, &username);
    let cracker = cx.boxed(RefCell::new(Cracker {
        hash,
        callback,
        shutdown,
        threads,
        salt,
        terminate: Arc::new(AtomicBool::new(false)),
        counter: Arc::new(AtomicIsize::new(0)),
        queue: Arc::new(queue),
    }));
    Ok(cracker)
}
pub fn get_counter(mut cx: FunctionContext) -> JsResult<JsNumber> {
    let cracker = cx.argument::<BoxedCracker>(0)?;
    let cracker = cracker.borrow();
    let counter = cx.number(cracker.get_counter() as f64);
    Ok(counter)
}
pub fn get_salt(mut cx: FunctionContext) -> JsResult<JsString> {
    let cracker = cx.argument::<BoxedCracker>(0)?;
    let cracker = cracker.borrow();
    let salt = cx.string(cracker.get_salt());
    Ok(salt)
}

pub fn cracker_crack_using_password_file(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let hasher = cx.argument::<BoxedCracker>(0)?;
    let hasher = hasher.borrow();
    let algorithm = cx.argument::<JsString>(1)?.value(&mut cx);
    let file_path = cx.argument::<JsString>(2)?.value(&mut cx);
    let buff_size = cx.argument::<JsNumber>(3)?.value(&mut cx) as u64;
    hasher.cracker_crack_using_password_file(cx, &algorithm, &file_path, buff_size)
}

pub fn get_algorithms(mut cx: FunctionContext) -> JsResult<JsArray> {
    let results = JsArray::new(&mut cx, ALGORITHMS.len() as u32);
    for (i, algorithm) in ALGORITHMS.iter().enumerate() {
        let value = cx.string(algorithm);
        results.set(&mut cx, i as u32, value).ok();
    }
    Ok(results)
}
pub fn get_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let cracker = cx.argument::<BoxedCracker>(0)?;
    let cracker = cracker.borrow();
    let hash = cx.string(cracker.get_hash());
    Ok(hash)
}
