from gensim.models import Word2Vec
from pathlib import Path
import pandas as pd
import logging
import os
import argparse
import numpy as np
import random
random.seed(7)


# Note that for a fully deterministically-reproducible run, you must also limit the model to a single worker thread (workers=1), to eliminate ordering jitter from OS thread scheduling.

import pickle


def get_routes_from_path(path):
    routes = []
    counter = 0
    df = pd.read_csv(path, sep='|', header=None, low_memory=False)
    s = df.iloc[:, 6].dropna().drop_duplicates()

    # 定义去重并过滤函数
    def dedup_and_filter(x):
        words = x.split()
        # 去除含有'{'或'}'的单词
        if any('{' in word or '}' in word for word in words):
            return None
        # 单词去重并保持顺序
        seen = set()
        deduped = []
        for word in words:
            if word not in seen:
                deduped.append(word)
                seen.add(word)
        return ' '.join(deduped)

    # 应用函数，去重并过滤
    result = s.apply(dedup_and_filter).dropna()
    result = result.drop_duplicates()
    for value in result:
        as_path = value.split()
        routes.append(as_path)
        counter += 1
    logging.info(("Extracted", counter, "routes from ", path))
    return routes

class BGP2VEC:
    def __init__(self, model_path, path=None, rewrite=False, embedding_size=32, negative=5, epochs=3, window=2,
                 word_fq_dict=None):

        self.model_path = model_path
        self.model = None
        self.embedding_size = embedding_size
        self.word_fq_dict = word_fq_dict

        if rewrite or not self.import_model():
            logging.info(("Start generating BGP2VEC model for ", path))
            self.routes = get_routes_from_path(path)
            self.build_model(embedding_size, window, negative, epochs)
            self.export_model()

    def build_model(self, embedding_size, window, negative, epochs):
        self.model = Word2Vec(vector_size=embedding_size, min_count=1, window=window, sg=1, hs=0, negative=negative,
                              workers=1, epochs=1, seed=7)
        if self.word_fq_dict:
            self.model.build_vocab_from_freq(self.word_fq_dict)
        else:
            self.model.build_vocab(self.routes, progress_per=1000000)
        logging.info(("Vocabulary size:", len(self.model.wv.key_to_index)))

        logging.info("Start training model")
        self.model.train(self.routes, total_examples=len(self.routes), epochs=epochs, report_delay=30)

    def export_model(self):
        asn_vectors = {}
        for asn in self.model.wv.key_to_index:
            asn_vectors[str(asn)] = self.model.wv[asn].tolist()
        with open(self.model_path, 'wb') as f:
            pickle.dump(asn_vectors, f)
        logging.info(('Exported:', self.model_path))

    def import_model(self):
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                asn_vectors = pickle.load(f)
            self.embedding_size = next(iter(asn_vectors.values())).__len__()
            self.model = asn_vectors
            logging.info(('Imported:', self.model_path))
            return True
        else:
            logging.info(("No exist:", self.model_path))
            return False

    def asn2idx(self, asn):
        asn_str = str(asn)
        if asn_str in self.model:
            return list(self.model.keys()).index(asn_str)
        raise KeyError(asn)

    def idx2asn(self, idx):
        return list(self.model.keys())[idx]

    def asn2vec(self, asn):
        return np.array(self.model[str(asn)])

    def vec2asn(self, vec):
        vec = np.array(vec)
        best_match = None
        best_sim = -1
        for asn, v in self.model.items():
            v_arr = np.array(v)
            sim = np.dot(vec, v_arr) / (np.linalg.norm(vec) * np.linalg.norm(v_arr) + 1e-10)
            if sim > best_sim:
                best_sim = sim
                best_match = asn
        return best_match

    def routes_asn2idx(self, routes, max_len):
        routes_idx = np.zeros([len(routes), max_len], dtype=np.int32)

        for i, route in enumerate(routes):
            for t, asn in enumerate(route):
                routes_idx[i, t] = self.asn2idx(asn)
        return routes_idx

    def asns_asn2vec(self, asns):
        asns_vec = np.zeros([len(asns), self.embedding_size])

        for i, asn in enumerate(asns):
            asns_vec[i, :] = self.asn2vec(asn)

        return asns_vec
    
if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Train BGP2VEC AS embeddings")
    parser.add_argument("--rib-path", required=True, help="RIB text dump used for training")
    parser.add_argument(
        "--model-path",
        default=str(root / "data" / "embs" / "as_embeddings.pkl"),
        help="Output pickle path under data/embs/",
    )
    args = parser.parse_args()
    BGP2VEC(args.model_path, args.rib_path)
