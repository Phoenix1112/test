#!/usr/bin/env python3


"""
massdns-wildcard-filter.py

Massdns çıktısındaki wildcard DNS kayıtlarını IP ve CNAME hedeflerine göre filtreler.
Sadece benzersiz subdomain adlarını çıktı verir.

Kullanım:
    python3 massdns-wildcard-filter.py -f massdns_output.txt -o output.txt -t 10

Parametreler:
    -f, --file      Girdi dosyası (zorunlu)
    -t, --threshold Eşik değeri (varsayılan: 10). Aynı IP veya CNAME hedefine sahip
                    benzersiz subdomain sayısı bu değeri aşıyorsa, o IP/CNAME'ye
                    sahip TÜM subdomainler filtrelenir.
    -o, --output    Çıktı dosyası (varsayılan: filtered_massdns_output.txt)
    -v, --verbose   Detaylı çıktı
"""

import argparse
import sys
from collections import defaultdict


def parse_args():
    parser = argparse.ArgumentParser(
        description="Massdns wildcard filtreleyici. Aynı IP/CNAME'den eşik değerini aşan tüm kayıtları siler.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  python3 %(prog)s -f massdns.txt
  python3 %(prog)s -f massdns.txt -t 15 -o temiz.txt
  python3 %(prog)s -f massdns.txt -t 5 -v
        """
    )
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='Massdns çıktı dosyası (zorunlu)'
    )
    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=10,
        help='Wildcard eşik değeri (varsayılan: 10)'
    )
    parser.add_argument(
        '-o', '--output',
        default='filtered_massdns_output.txt',
        help='Çıktı dosyası (varsayılan: filtered_massdns_output.txt)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Detaylı çıktı göster'
    )
    return parser.parse_args()


def parse_line(line):
    """Massdns satırını ayrıştırır."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    parts = line.split()
    if len(parts) < 3:
        return None

    subdomain = parts[0].rstrip('.')
    record_type = parts[1]

    if record_type == 'A' and len(parts) >= 3:
        value = parts[2]
    elif record_type == 'CNAME' and len(parts) >= 3:
        value = ' '.join(parts[2:]).rstrip('.')
    else:
        return None

    return {
        'subdomain': subdomain,
        'type': record_type,
        'value': value,
        'raw': line
    }


def main():
    args = parse_args()

    # Tüm kayıtları oku
    all_records = []
    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            for line in f:
                parsed = parse_line(line)
                if parsed:
                    all_records.append(parsed)
    except FileNotFoundError:
        print(f"[HATA] Dosya bulunamadı: {args.file}")
        sys.exit(1)
    except Exception as e:
        print(f"[HATA] Dosya okunurken hata: {e}")
        sys.exit(1)

    if not all_records:
        print("[UYARI] Dosyada işlenecek kayıt bulunamadı.")
        sys.exit(0)

    # A kayıtları: IP -> benzersiz subdomain seti
    ip_to_subdomains = defaultdict(set)
    # CNAME kayıtları: target -> benzersiz subdomain seti
    cname_to_subdomains = defaultdict(set)

    for rec in all_records:
        if rec['type'] == 'A':
            ip_to_subdomains[rec['value']].add(rec['subdomain'])
        elif rec['type'] == 'CNAME':
            cname_to_subdomains[rec['value']].add(rec['subdomain'])

    # Wildcard IP'leri tespit et (eşik değerini aşanlar)
    wildcard_ips = set()
    for ip, subdomains in ip_to_subdomains.items():
        if len(subdomains) > args.threshold:
            wildcard_ips.add(ip)

    # Wildcard CNAME target'larını tespit et (eşik değerini aşanlar)
    wildcard_cnames = set()
    for target, subdomains in cname_to_subdomains.items():
        if len(subdomains) > args.threshold:
            wildcard_cnames.add(target)

    # Filtrele - sadece benzersiz subdomain'leri tut
    seen_subdomains = set()
    filtered_subdomains = []
    removed_count = 0
    removed_unique = set()

    for rec in all_records:
        subdomain = rec['subdomain']

        # Wildcard kontrolü
        is_wildcard = False
        if rec['type'] == 'A' and rec['value'] in wildcard_ips:
            is_wildcard = True
        elif rec['type'] == 'CNAME' and rec['value'] in wildcard_cnames:
            is_wildcard = True

        if is_wildcard:
            removed_count += 1
            removed_unique.add(subdomain)
            continue

        # Duplicate kontrolü - aynı subdomain daha önce eklendiyse atla
        if subdomain in seen_subdomains:
            continue

        seen_subdomains.add(subdomain)
        filtered_subdomains.append(subdomain)

    # Sonuçları yaz - sadece subdomain adları, her biri bir kez
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            for subdomain in filtered_subdomains:
                f.write(subdomain + '\n')
    except Exception as e:
        print(f"[HATA] Çıktı dosyası yazılırken hata: {e}")
        sys.exit(1)

    # İstatistikler
    print(f"\n{'='*60}")
    print(f"  MASSDNS WILDCARD FİLTRELEME SONUÇLARI")
    print(f"{'='*60}")
    print(f"  Eşik değeri (threshold):  {args.threshold}")
    print(f"  Toplam kayıt (satır):     {len(all_records)}")
    print(f"  Filtrelenen satır:        {removed_count}")
    print(f"  Filtrelenen benzersiz:    {len(removed_unique)}")
    print(f"  Kalan benzersiz subdomain:{len(filtered_subdomains)}")
    print(f"  Wildcard IP sayısı:       {len(wildcard_ips)}")
    print(f"  Wildcard CNAME sayısı:    {len(wildcard_cnames)}")
    print(f"{'='*60}")
    print(f"  Çıktı dosyası: {args.output}")

    if args.verbose:
        if wildcard_ips:
            print(f"\n  [WILDCARD IP'ler] ({len(wildcard_ips)} adet):")
            for ip in sorted(wildcard_ips):
                count = len(ip_to_subdomains[ip])
                print(f"    - {ip}  ({count} subdomain)")

        if wildcard_cnames:
            print(f"\n  [WILDCARD CNAME'ler] ({len(wildcard_cnames)} adet):")
            for target in sorted(wildcard_cnames):
                count = len(cname_to_subdomains[target])
                print(f"    - {target}  ({count} subdomain)")

        if removed_unique:
            print(f"\n  [Silinen benzersiz subdomain'ler] (ilk 20):")
            for subdomain in sorted(list(removed_unique))[:20]:
                print(f"    - {subdomain}")

    print()


if __name__ == '__main__':
    main()
