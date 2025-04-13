use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ipcrypt2::{Ipcrypt, IpcryptNdx};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn deterministic_encryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Deterministic Encryption");
    let ipcrypt = Ipcrypt::new_random();
    let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    // String-based encryption
    group.bench_function("IPv4 Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt.encrypt_ip_str(black_box("192.168.1.1")).unwrap());
        })
    });
    group.bench_function("IPv4 Decrypt", |b| {
        let encrypted = ipcrypt.encrypt_ip_str("192.168.1.1").unwrap();
        b.iter(|| {
            black_box(ipcrypt.decrypt_ip_str(black_box(&encrypted)).unwrap());
        })
    });
    group.bench_function("IPv6 Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt.encrypt_ip_str(black_box("2001:db8::1")).unwrap());
        })
    });
    group.bench_function("IPv6 Decrypt", |b| {
        let encrypted = ipcrypt.encrypt_ip_str("2001:db8::1").unwrap();
        b.iter(|| {
            black_box(ipcrypt.decrypt_ip_str(black_box(&encrypted)).unwrap());
        })
    });

    // Raw IP address encryption
    group.bench_function("IPv4 Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt.encrypt_ipaddr(black_box(ipv4)).unwrap());
        })
    });
    group.bench_function("IPv4 Decrypt", |b| {
        let encrypted = ipcrypt.encrypt_ipaddr(ipv4).unwrap();
        b.iter(|| {
            black_box(ipcrypt.decrypt_ipaddr(black_box(encrypted)).unwrap());
        })
    });
    group.bench_function("IPv6 Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt.encrypt_ipaddr(black_box(ipv6)).unwrap());
        })
    });
    group.bench_function("IPv6 Decrypt", |b| {
        let encrypted = ipcrypt.encrypt_ipaddr(ipv6).unwrap();
        b.iter(|| {
            black_box(ipcrypt.decrypt_ipaddr(black_box(encrypted)).unwrap());
        })
    });
}

fn non_deterministic_encryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Non-deterministic Encryption");
    let ipcrypt = Ipcrypt::new_random();
    let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    // String-based encryption
    group.bench_function("IPv4 Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt.nd_encrypt_ip_str(black_box("192.168.1.1")).unwrap());
        })
    });
    group.bench_function("IPv4 Decrypt", |b| {
        let encrypted = ipcrypt.nd_encrypt_ip_str("192.168.1.1").unwrap();
        b.iter(|| {
            black_box(ipcrypt.nd_decrypt_ip_str(black_box(&encrypted)).unwrap());
        })
    });
    group.bench_function("IPv6 Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt.nd_encrypt_ip_str(black_box("2001:db8::1")).unwrap());
        })
    });
    group.bench_function("IPv6 Decrypt", |b| {
        let encrypted = ipcrypt.nd_encrypt_ip_str("2001:db8::1").unwrap();
        b.iter(|| {
            black_box(ipcrypt.nd_decrypt_ip_str(black_box(&encrypted)).unwrap());
        })
    });

    // Raw IP address encryption
    group.bench_function("IPv4 ND Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt.nd_encrypt_ipaddr(black_box(ipv4)).unwrap());
        })
    });
    group.bench_function("IPv4 ND Decrypt", |b| {
        let encrypted = ipcrypt.nd_encrypt_ipaddr(ipv4).unwrap();
        b.iter(|| {
            black_box(ipcrypt.nd_decrypt_ipaddr(black_box(encrypted)).unwrap());
        })
    });
    group.bench_function("IPv6 ND Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt.nd_encrypt_ipaddr(black_box(ipv6)).unwrap());
        })
    });
    group.bench_function("IPv6 ND Decrypt", |b| {
        let encrypted = ipcrypt.nd_encrypt_ipaddr(ipv6).unwrap();
        b.iter(|| {
            black_box(ipcrypt.nd_decrypt_ipaddr(black_box(encrypted)).unwrap());
        })
    });
}

fn ndx_encryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("NDX Encryption");
    let ipcrypt_ndx = IpcryptNdx::new_random();
    let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    // String-based encryption
    group.bench_function("IPv4 Encrypt", |b| {
        b.iter(|| {
            black_box(
                ipcrypt_ndx
                    .nd_encrypt_ip_str(black_box("192.168.1.1"))
                    .unwrap(),
            );
        })
    });
    group.bench_function("IPv4 Decrypt", |b| {
        let encrypted = ipcrypt_ndx.nd_encrypt_ip_str("192.168.1.1").unwrap();
        b.iter(|| {
            black_box(
                ipcrypt_ndx
                    .nd_decrypt_ip_str(black_box(&encrypted))
                    .unwrap(),
            );
        })
    });
    group.bench_function("IPv6 Encrypt", |b| {
        b.iter(|| {
            black_box(
                ipcrypt_ndx
                    .nd_encrypt_ip_str(black_box("2001:db8::1"))
                    .unwrap(),
            );
        })
    });
    group.bench_function("IPv6 Decrypt", |b| {
        let encrypted = ipcrypt_ndx.nd_encrypt_ip_str("2001:db8::1").unwrap();
        b.iter(|| {
            black_box(
                ipcrypt_ndx
                    .nd_decrypt_ip_str(black_box(&encrypted))
                    .unwrap(),
            );
        })
    });

    // Raw IP address encryption
    group.bench_function("IPv4 NDX Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt_ndx.nd_encrypt_ipaddr(black_box(ipv4)).unwrap());
        })
    });
    group.bench_function("IPv4 NDX Decrypt", |b| {
        let encrypted = ipcrypt_ndx.nd_encrypt_ipaddr(ipv4).unwrap();
        b.iter(|| {
            black_box(ipcrypt_ndx.nd_decrypt_ipaddr(black_box(encrypted)).unwrap());
        })
    });
    group.bench_function("IPv6 NDX Encrypt", |b| {
        b.iter(|| {
            black_box(ipcrypt_ndx.nd_encrypt_ipaddr(black_box(ipv6)).unwrap());
        })
    });
    group.bench_function("IPv6 NDX Decrypt", |b| {
        let encrypted = ipcrypt_ndx.nd_encrypt_ipaddr(ipv6).unwrap();
        b.iter(|| {
            black_box(ipcrypt_ndx.nd_decrypt_ipaddr(black_box(encrypted)).unwrap());
        })
    });
}

fn key_generation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Generation");

    group.bench_function("Ipcrypt", |b| {
        b.iter(|| {
            black_box(Ipcrypt::generate_key());
        })
    });

    group.bench_function("IpcryptNdx", |b| {
        b.iter(|| {
            black_box(IpcryptNdx::generate_key());
        })
    });
}

criterion_group!(
    benches,
    deterministic_encryption_benchmark,
    non_deterministic_encryption_benchmark,
    ndx_encryption_benchmark,
    key_generation_benchmark
);
criterion_main!(benches);
