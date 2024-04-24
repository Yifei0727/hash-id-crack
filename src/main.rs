use std::io::BufRead;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::thread;

use clap::Parser;
use digest::Digest;
use indicatif::{ProgressBar, ProgressStyle};
use sm3::Sm3;

use crate::HashType::{
    MD5, SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SM3,
};

#[derive(Parser, Debug, Clone)]
struct Args {
    /// 原始清单文件，每行1条记录
    #[clap(short, long, help = "原始清单文件路径，文件中每行1条按行读取进行计算")]
    file: String,
    /// 目标值文件，每行1条记录
    #[clap(short, long, help = "目标值文件路径，每行一个期望的哈希值(hex格式)")]
    expect: String,
    #[clap(
        long,
        help = "更改摘要算法，默认为SM3，支持 MD5,SHA1,SHA256等",
        default_value = "SM3"
    )]
    hash: Option<String>,
    /// 跳过 多少行（如上次终端 可以继续）
    offset: Option<usize>,
    #[clap(long, help = "是否输出调试信息")]
    debug: Option<bool>,
}

fn read_except_file(file: &str, hash_type: &HashType) -> Vec<Vec<u8>> {
    let mut res = Vec::new();
    let file = std::fs::File::open(file).unwrap();
    let reader = std::io::BufReader::new(file);
    for line in reader.lines() {
        let hash = hex::decode(line.unwrap().trim()).unwrap();
        if res.iter().any(|e: &Vec<u8>| e.eq(&hash)) {
            eprintln!("跳过重复的哈希值: {:?}", hex::encode(&hash));
            continue;
        } else {
            if hash.len() == hash_type.length() {
                res.push(hash)
            } else {
                eprintln!("跳过预期不一致的哈希值长度: {:?}", hex::encode(&hash));
                continue;
            }
        }
    }
    res
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
enum HashType {
    SM3,
    MD5,
    SHA1,
    SHA2_224,
    SHA2_256,
    SHA2_384,
    SHA2_512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl HashType {
    /// 获取哈希值长度 (字节)
    fn length(&self) -> usize {
        match self {
            SM3 => 32,
            MD5 => 16,
            SHA1 => 20,
            SHA2_224 => 28,
            SHA2_256 => 32,
            SHA2_384 => 48,
            SHA2_512 => 64,
            SHA3_224 => 28,
            SHA3_256 => 32,
            SHA3_384 => 48,
            SHA3_512 => 64,
        }
    }
}

impl From<String> for HashType {
    fn from(value: String) -> Self {
        if value.to_uppercase().eq("SM3") {
            SM3
        } else if value.to_uppercase().eq("MD5") || value.to_uppercase().eq("MD-5") {
            MD5
        } else if value.to_uppercase().eq("SHA1") || value.to_uppercase().eq("SHA-1") {
            SHA1
        } else if value.to_uppercase().eq("SHA224")
            || value.to_uppercase().eq("SHA-224")
            || value.to_uppercase().eq("SHA2-224")
        {
            SHA2_224
        } else if value.to_uppercase().eq("SHA256")
            || value.to_uppercase().eq("SHA-256")
            || value.to_uppercase().eq("SHA2-256")
        {
            SHA2_256
        } else if value.to_uppercase().eq("SHA384")
            || value.to_uppercase().eq("SHA-384")
            || value.to_uppercase().eq("SHA2-384")
        {
            SHA2_384
        } else if value.to_uppercase().eq("SHA512")
            || value.to_uppercase().eq("SHA-512")
            || value.to_uppercase().eq("SHA2-512")
        {
            SHA2_512
        } else if value.to_uppercase().eq("SHA3-224") {
            SHA3_224
        } else if value.to_uppercase().eq("SHA3-256") {
            SHA3_256
        } else if value.to_uppercase().eq("SHA3-384") {
            SHA3_384
        } else if value.to_uppercase().eq("SHA3-512") {
            SHA3_512
        } else {
            eprintln!("未知的哈希算法: {} ，使用默认SM3算法", value);
            SM3
        }
    }
}

fn is_hash_in_except_list<T>(hash: &T, except_list: &Vec<T>) -> bool
where
    T: PartialEq,
{
    except_list.iter().any(|e| e == hash)
}

fn calc_hash(id: &[u8], method: HashType) -> Vec<u8> {
    match method {
        SM3 => {
            let mut hasher: Sm3 = Sm3::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
        MD5 => md5::compute(id).to_vec(),
        SHA1 => {
            let mut hasher = sha1::Sha1::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
        SHA2_224 => {
            let mut hasher = sha2::Sha224::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
        SHA2_256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
        SHA2_384 => {
            let mut hasher = sha2::Sha384::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
        SHA2_512 => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
        SHA3_224 => {
            let mut hasher = sha3::Sha3_224::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
        SHA3_256 => {
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
        SHA3_384 => {
            let mut hasher = sha3::Sha3_384::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
        SHA3_512 => {
            let mut hasher = sha3::Sha3_512::new();
            hasher.update(id);
            hasher.finalize().to_vec()
        }
    }
}

#[derive(Debug, Default)]
struct IdMap {
    id: String,
    hash: String,
}

impl IdMap {
    fn new(id: String, hash: String) -> IdMap {
        IdMap { id, hash }
    }
}

fn main() {
    // 1. 解析参数并读取 目标值文件（较少，一次性读取后放入内存）
    // 2. 并发读取原始清单文件，计算哈希值，判断是否在目标值文件中， 若存在则输出并记录
    // 3. resume 模式支持 从上次中断处继续

    let args: Args = Args::parse();
    let method_hash: HashType =
        HashType::from(args.hash.clone().unwrap_or_else(|| "SM3".to_string()));
    let except_list = read_except_file(&args.expect, &method_hash);
    let file = std::fs::File::open(&args.file).unwrap();
    let reader = std::io::BufReader::new(file);
    // 生产消费模型 文件读取线程生产数据，核心线程消费数据
    // let (tx, rx): (Sender<String>, _) = channel();
    let (tx, rx) = sync_channel(1);
    let start_id = args.offset.unwrap_or(0) as u64;
    let products_cnt = Arc::new(AtomicU64::new(0));
    let products_id_w = products_cnt.clone();
    thread::spawn(move || {
        for line in reader.lines() {
            let line = line.unwrap().trim().to_string();
            if line.is_empty() {
                continue;
            }
            if products_id_w.fetch_add(1, Ordering::SeqCst) < start_id {
                continue;
            }
            tx.send(line).unwrap();
        }
    });

    // 获取CPU核心数 每核心提供一个线程
    let core_num = num_cpus::get();
    let rx = Arc::new(Mutex::new(rx));

    let execute_cnt = Arc::new(AtomicU64::new(0));

    let result_set: Arc<Mutex<Vec<IdMap>>> = Arc::new(Mutex::new(Vec::new()));
    let mut exec_thread_list = Vec::new();
    for _ in 0..core_num {
        let execute_cnt_w = execute_cnt.clone();
        let result_set_w = Arc::clone(&result_set);
        let except_list = except_list.clone();
        let thread_rx = Arc::clone(&rx);
        let args = args.clone();
        // 消费者
        exec_thread_list.push(thread::spawn(move || loop {
            let id = thread_rx.lock().unwrap().recv();
            if id.is_err() {
                if (&args).debug.unwrap_or(false) {
                    eprintln!("thread exit : {}", id.err().unwrap());
                }
                break;
            }
            let id = id.unwrap();
            let hash = calc_hash(id.as_bytes(), (&method_hash).clone());
            if is_hash_in_except_list(&hash, &except_list) {
                println!("found {}: {:?}", id, hex::encode(&hash));
                result_set_w
                    .lock()
                    .unwrap()
                    .push(IdMap::new(id, hex::encode(&hash)));
            }
            execute_cnt_w.fetch_add(1, Ordering::SeqCst);
        }));
    }
    let pb = ProgressBar::new(products_cnt.load(Ordering::SeqCst));
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}",
            )
            .expect("???")
            .progress_chars("#>-"),
    );
    loop {
        thread::sleep(std::time::Duration::from_secs(1));
        pb.set_message(format!(
            "except_list: {:?}, found {}",
            except_list.len(),
            Arc::clone(&result_set).lock().unwrap().len()
        ));
        pb.set_position(execute_cnt.load(Ordering::SeqCst));
        pb.set_length(products_cnt.load(Ordering::SeqCst));
        if except_list.len() == Arc::clone(&result_set).lock().unwrap().len() {
            break;
        }
        if exec_thread_list.iter().all(|e| e.is_finished()) {
            if (&args).debug.unwrap_or(false) {
                eprintln!(
                    "all thread exit {} {}",
                    &pb.position(),
                    &pb.length().unwrap_or_else(|| 0)
                );
            }
            break;
        }
    }
    println!("---------------------------------");
    for (index, value) in result_set.lock().unwrap().iter().enumerate() {
        println!("{},{},{}", index, value.id, value.hash);
    }
    println!("---------------------------------");
}
