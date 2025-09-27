#!/usr/bin/env python3
# generate_hashes.py
# Автоматически находит все JAR и EXE файлы в директории
# Вычисляет size, sha256 и извлекает версию
# Результат записывается в hashes.json

import hashlib
import json
import os
import zipfile
import re
import sys
import glob

try:
    import pefile
except Exception:
    pefile = None

def find_files():
    """Находит все JAR и EXE файлы в текущей директории"""
    jar_files = glob.glob("*.jar") + glob.glob("*.JAR")
    exe_files = glob.glob("*.exe") + glob.glob("*.EXE")
    
    # Исключаем временные файлы и бэкапы
    jar_files = [f for f in jar_files if not any(x in f.lower() for x in ['temp', 'backup', 'old', 'bak'])]
    exe_files = [f for f in exe_files if not any(x in f.lower() for x in ['temp', 'backup', 'old', 'bak'])]
    
    # Сортируем по дате изменения (новейшие первыми)
    jar_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    exe_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    # Берем только самые новые файлы каждого типа
    latest_jar = jar_files[0] if jar_files else None
    latest_exe = exe_files[0] if exe_files else None
    
    files = []
    if latest_jar:
        files.append(latest_jar)
        print(f"📦 Найден JAR файл: {latest_jar}")
    
    if latest_exe:
        files.append(latest_exe)
        print(f"🪟 Найден EXE файл: {latest_exe}")
    
    if not files:
        print("❌ Не найдено JAR или EXE файлов в директории")
        print("Доступные файлы:", os.listdir('.'))
    
    return files

def sha256sum(filename, block_size=1 << 16):
    """Вычисляет SHA-256 хеш файла"""
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_manifest_bytes(b):
    """Парсит MANIFEST.MF из JAR файла"""
    try:
        s = b.decode('utf-8', errors='replace')
    except Exception:
        s = str(b)
    d = {}
    # Обрабатываем многострочные значения в манифесте
    lines = s.splitlines()
    current_key = None
    current_value = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if ':' in line and not line.startswith(' '):
            # Сохраняем предыдущую пару ключ-значение
            if current_key and current_value:
                d[current_key] = ' '.join(current_value).strip()
            
            # Начинаем новую пару
            k, v = line.split(':', 1)
            current_key = k.strip()
            current_value = [v.strip()]
        elif current_key and line.startswith(' '):
            # Продолжение предыдущего значения
            current_value.append(line.strip())
        else:
            # Новая строка без отступа - начинаем новую пару
            if current_key and current_value:
                d[current_key] = ' '.join(current_value).strip()
            current_key = None
            current_value = []
    
    # Сохраняем последнюю пару
    if current_key and current_value:
        d[current_key] = ' '.join(current_value).strip()
    
    return d

def parse_properties_bytes(b):
    """Парсит properties файлы"""
    try:
        s = b.decode('utf-8', errors='replace')
    except Exception:
        s = str(b)
    props = {}
    for line in s.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        props[k.strip()] = v.strip()
    return props

def get_version_from_jar(path):
    """Извлекает версию из JAR файла"""
    try:
        with zipfile.ZipFile(path, 'r') as z:
            # 1) Ищем MANIFEST.MF
            manifest_name = None
            for name in z.namelist():
                if 'META-INF/MANIFEST.MF' in name.upper():
                    manifest_name = name
                    break
            
            if manifest_name:
                try:
                    mbytes = z.read(manifest_name)
                    m = parse_manifest_bytes(mbytes)
                    
                    # Приоритет ключей для версии
                    version_keys = [
                        'Implementation-Version',
                        'Specification-Version', 
                        'Bundle-Version',
                        'Version',
                        'Project-Version'
                    ]
                    
                    for key in version_keys:
                        if key in m and m[key].strip():
                            version = m[key].strip()
                            # Убираем лишние пробелы и переносы
                            version = ' '.join(version.split())
                            return version
                except Exception as e:
                    print(f"[warn] Ошибка чтения манифеста: {e}")
            
            # 2) Ищем pom.properties
            for name in z.namelist():
                if 'pom.properties' in name.lower() and 'maven' in name.lower():
                    try:
                        pbytes = z.read(name)
                        props = parse_properties_bytes(pbytes)
                        if 'version' in props and props['version'].strip():
                            return props['version'].strip()
                    except Exception:
                        pass
            
            # 3) Ищем в имени файла
            filename = os.path.basename(path)
            version_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', filename)
            if version_match:
                return version_match.group(1)
                
    except Exception as e:
        print(f"[warn] Ошибка чтения JAR {path}: {e}")
    return None

def get_version_from_exe(path):
    """Извлекает версию из EXE файла"""
    # 1) Пытаемся через pefile
    if pefile:
        try:
            pe = pefile.PE(path)
            if hasattr(pe, 'FileInfo') and pe.FileInfo:
                for fileinfo in pe.FileInfo:
                    if hasattr(fileinfo, 'Key') and fileinfo.Key.decode(errors='ignore') == 'StringFileInfo':
                        for st in fileinfo.StringTable:
                            for entry in st.entries.items():
                                key = entry[0].decode(errors='ignore') if isinstance(entry[0], bytes) else str(entry[0])
                                value = entry[1].decode(errors='ignore') if isinstance(entry[1], bytes) else str(entry[1])
                                if key in ('FileVersion', 'ProductVersion', 'Version') and value.strip():
                                    # Очищаем версию от лишних символов
                                    version = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', value)
                                    if version:
                                        return version.group(1)
                                    return value.strip()
        except Exception as e:
            print(f"[warn] Ошибка pefile для {path}: {e}")
    
    # 2) Поиск в бинарных данных
    try:
        with open(path, 'rb') as f:
            # Читаем первые 500KB для поиска версии
            data = f.read(500000)
        
        # Ищем версию в разных форматах
        version_patterns = [
            rb'(\d+\.\d+\.\d+\.\d+)',  # 1.2.3.4
            rb'(\d+\.\d+\.\d+)',       # 1.2.3
            rb'v?(\d+\.\d+)',          # 1.2 или v1.2
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, data)
            if matches:
                # Берем первую найденную версию
                for match in matches:
                    try:
                        version = match.decode('ascii', errors='ignore')
                        if version and len(version) <= 20:  # Фильтруем мусор
                            return version
                    except:
                        continue
                        
    except Exception as e:
        print(f"[warn] Ошибка поиска версии в EXE {path}: {e}")
    
    # 3) Ищем в имени файла
    filename = os.path.basename(path)
    version_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', filename)
    if version_match:
        return version_match.group(1)
    
    return None

def get_file_info(filepath):
    """Получает всю информацию о файле"""
    info = {"size": None, "sha256": None, "version": None}
    
    if not os.path.exists(filepath):
        return info
    
    try:
        # Размер файла
        info["size"] = os.path.getsize(filepath)
    except Exception as e:
        print(f"[error] Не удалось получить размер {filepath}: {e}")
    
    try:
        # SHA-256 хеш
        print(f"🔍 Вычисляю хеш для {filepath}...")
        info["sha256"] = sha256sum(filepath)
    except Exception as e:
        print(f"[error] Не удалось вычислить хеш {filepath}: {e}")
    
    try:
        # Версия
        if filepath.lower().endswith('.jar'):
            info["version"] = get_version_from_jar(filepath)
        elif filepath.lower().endswith('.exe'):
            info["version"] = get_version_from_exe(filepath)
        
        if info["version"]:
            print(f"✅ Версия {filepath}: {info['version']}")
        else:
            print(f"⚠️ Версия для {filepath} не найдена")
            
    except Exception as e:
        print(f"[error] Ошибка определения версии {filepath}: {e}")
    
    return info

def main():
    """Основная функция"""
    print("🚀 Поиск JAR и EXE файлов...")
    
    files = find_files()
    if not files:
        print("❌ Файлы не найдены. Создаю пустой hashes.json")
        with open("hashes.json", "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2, ensure_ascii=False)
        return
    
    result = {}
    
    for filepath in files:
        print(f"\n📄 Обрабатываю: {filepath}")
        result[filepath] = get_file_info(filepath)
    
    # Сохраняем результат
    with open("hashes.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ hashes.json успешно обновлен!")
    print("📊 Результат:")
    for filename, info in result.items():
        print(f"   {filename}:")
        print(f"     Размер: {info['size']} байт")
        print(f"     SHA-256: {info['sha256']}")
        print(f"     Версия: {info['version'] or 'Не определена'}")
    
    # Предупреждение если pefile не установлен
    if not pefile:
        print("\n⚠️ Для лучшего определения версий EXE файлов установите:")
        print("pip install pefile")

if __name__ == "__main__":
    main()