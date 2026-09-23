"""
BGP 数据库初始化脚本

功能：
1. 从 data/pfx2as/ 目录下的 .pfx2as 文件创建 pfx2as_{日期} 表（前缀到 AS 映射）
2. 从 data/rel/ 目录下的 .bz2 文件创建 rel_{年月} 表（AS 关系）

所有表都存储在 data/db/bgp.db 中
"""

import pandas as pd
from pathlib import Path
from sqlalchemy import create_engine, text
import re
from glob import glob


# ============ AS 关系表 (rel_{年月}) ============

def create_rel_tables(engine) -> list:
    """
    创建 AS 关系表 rel_{年月}
    从 data/rel/ 目录下的所有 .bz2 文件读取数据
    处理 provider-customer (-1) 和 peer-peer (0) 关系
    """
    print("\n" + "="*60)
    print("步骤1: 创建 AS 关系表 (rel_*)")
    print("="*60)
    
    # 查找 data/rel 目录下的所有 .bz2 文件
    rel_dir = Path("./data/rel")
    rel_files = sorted(rel_dir.glob("*.bz2"))
    
    if not rel_files:
        print("  未找到任何 rel 文件，跳过")
        return []
    
    print(f"  找到 {len(rel_files)} 个文件:")
    for f in rel_files:
        print(f"    - {f.name}")
    
    table_info = []
    total_rows = 0
    
    for filepath in rel_files:
        print(f"\n  处理文件: {filepath.name}")
        
        try:
            # 读取文件：as1 | as2 | rel，tab分隔，无表头
            # .as-rel.txt.bz2 和 .as-rel2.txt.bz2 格式相同
            df = pd.read_csv(
                filepath,
                compression="bz2",
                comment="#",
                sep="|",
                header=None,
                usecols=[0, 1, 2],
                names=["as1", "as2", "rel"],
                dtype={"as1": "string", "as2": "string", "rel": "int8"}
            )
            
            # 对 rel=-1 的行，生成反向 rel=1 的补充数据
            df_rev = df.loc[df["rel"] == -1, ["as1", "as2"]].copy()
            df_rev = df_rev.rename(columns={"as1": "as2", "as2": "as1"})
            df_rev["rel"] = 1
            
            # 合并并去重
            df_all = pd.concat([df, df_rev], ignore_index=True).drop_duplicates(subset=["as1", "as2", "rel"])
            
            # 从文件名中提取年月（如 20150601 -> 201506）
            match = re.search(r"(\d{6})\d{2}\.(?:as-rel2?\.)?txt\.bz2", filepath.name)
            if not match:
                print(f"    无法从文件名中提取年月，跳过")
                continue
            
            yyyymm = match.group(1)
            table_name = f"rel_{yyyymm}"
            
            # 创建表结构
            create_sql = f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                as1 TEXT NOT NULL,
                as2 TEXT NOT NULL,
                rel INTEGER NOT NULL
            );
            """
            with engine.begin() as conn:
                conn.execute(text(create_sql))
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS idx_{table_name}_as1_as2 ON {table_name}(as1, as2);"))
            
            # 写入数据
            df_all.to_sql(table_name, engine, if_exists="replace", index=False, method="multi", chunksize=5000)
            
            print(f"    - 表名: {table_name}, 原始行数: {len(df)}, 处理后行数: {len(df_all)}")
            table_info.append((table_name, len(df_all)))
            total_rows += len(df_all)
            
        except Exception as e:
            print(f"    处理失败: {e}")
            continue
    
    print(f"\n  rel 表总行数: {total_rows}")
    return table_info


# ============ 前缀到 AS 表 (pfx2as_{日期}) ============

def split_as_field(s: str) -> list:
    """拆分 AS 字段，处理 AS set、Multi-origin 和单个 AS"""
    s = (s or "").strip()
    if not s:
        return []
    
    # AS set: {32,54}
    if "," in s:
        return [p.strip() for p in s.split(",") if p.strip()]
    
    # Multi-origin: 10_20
    if "_" in s:
        return [p.strip() for p in s.split("_") if p.strip()]
    
    # Single AS
    return [s]


def create_pfx2as_tables(engine) -> list:
    """
    创建 pfx2as_{日期} 表
    从 data/pfx2as/ 目录下的所有 .pfx2as 文件读取数据
    """
    print("\n" + "="*60)
    print("步骤2: 创建前缀到 AS 表 (pfx2as_*)")
    print("="*60)
    
    # 查找 data/pfx2as 目录下的所有 .pfx2as 文件
    pfx2as_dir = Path("./data/pfx2as")
    pfx2as_files = sorted(pfx2as_dir.glob("*.pfx2as"))
    
    if not pfx2as_files:
        print("  未找到任何 .pfx2as 文件，跳过")
        return []
    
    print(f"  找到 {len(pfx2as_files)} 个文件:")
    for f in pfx2as_files:
        print(f"    - {f.name}")
    
    table_info = []
    total_rows = 0
    
    for filepath in pfx2as_files:
        print(f"\n  处理文件: {filepath.name}")
        
        try:
            # 读取文件：第1列(prefix) 和 第3列(AS)，tab分隔，无表头
            df = pd.read_csv(
                filepath,
                sep="\t",
                header=None,
                usecols=[0, 2],
                names=["prefix", "asn"],
                dtype=str
            )
            
            # 拆分 AS 字段
            df["asn"] = df["asn"].map(split_as_field)
            out = df.explode("asn", ignore_index=True)
            
            # 清理空值
            out = out[out["asn"].notna() & (out["asn"].astype(str).str.len() > 0)].reset_index(drop=True)
            
            # 从文件名中提取日期
            match = re.search(r"(\d{8})-\d{4}", filepath.stem)
            if not match:
                print(f"    无法从文件名中提取日期，跳过")
                continue
            
            date_str = match.group(1)
            table_name = f"pfx2as_{date_str}"
            
            # 写入数据库
            out.to_sql(table_name, engine, if_exists="replace", index=False, method="multi", chunksize=5000)
            
            # 建索引
            with engine.begin() as conn:
                conn.execute(text(f'CREATE INDEX IF NOT EXISTS "idx_{table_name}_prefix" ON "{table_name}"(prefix);'))
                conn.execute(text(f'CREATE INDEX IF NOT EXISTS "idx_{table_name}_asn" ON "{table_name}"(asn);'))
            
            print(f"    - 表名: {table_name}, 行数: {len(out)}")
            table_info.append((table_name, len(out)))
            total_rows += len(out)
            
        except Exception as e:
            print(f"    处理失败: {e}")
            continue
    
    print(f"\n  pfx2as 表总行数: {total_rows}")
    return table_info


# ============ 主函数 ============

def main():
    ROOT_DIR = Path(__file__).resolve().parent
    DB_DIR = ROOT_DIR / "data"
    DB_DIR.mkdir(parents=True, exist_ok=True)
    db_path = DB_DIR / "bgp.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    
    print("="*60)
    print("BGP 数据库初始化")
    print("="*60)
    print(f"数据库路径: {db_path}")
    
    # 创建 AS 关系表
    rel_tables = create_rel_tables(engine)
    
    # 创建前缀到 AS 表
    pfx2as_tables = create_pfx2as_tables(engine)
    
    # 汇总信息
    print("\n" + "="*60)
    print("初始化完成！汇总信息")
    print("="*60)
    print(f"数据库路径: {db_path}")
    
    # 列出所有表
    with engine.begin() as conn:
        result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"))
        tables = [row[0] for row in result]
        
        print(f"\n共创建 {len(tables)} 张表:")
        for i, t in enumerate(tables, 1):
            count_result = conn.execute(text(f'SELECT COUNT(*) FROM "{t}"'))
            count = count_result.scalar()
            print(f"  {i}. {t}: {count:,} 行")
        
        # 打印表结构
        print("\n表结构:")
        for t in tables:
            struct_result = conn.execute(text(f"PRAGMA table_info('{t}')"))
            cols = [row[1] for row in struct_result]
            print(f"  - {t}: {', '.join(cols)}")


if __name__ == "__main__":
    main()
