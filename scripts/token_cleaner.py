#!/usr/bin/env python3
import json
import time
import os
from datetime import datetime

def clean_expired_tokens():
    """清理过期令牌"""
    data_dir = "data"
    
    activations_path = os.path.join(data_dir, "activations.json")
    if not os.path.exists(activations_path):
        print("激活文件不存在")
        return
    
    with open(activations_path, 'r', encoding='utf-8') as f:
        activations = json.load(f)
    
    current_time = int(time.time())
    cleaned_count = 0
    
    if "activations" in activations:
        for work_id, activation in list(activations["activations"].items()):
            token = activation.get("token", {})
            expire_time = token.get("expire_time", 0)
            
            if expire_time < current_time and activation.get("status") == "active":
                activation["status"] = "expired"
                activation["expire_time"] = datetime.now().isoformat()
                cleaned_count += 1
        
        activations["last_updated"] = datetime.now().isoformat()
        
        with open(activations_path, 'w', encoding='utf-8') as f:
            json.dump(activations, f, indent=2, ensure_ascii=False)
        
        print(f"清理完成: 标记了 {cleaned_count} 个过期令牌")

if __name__ == "__main__":
    clean_expired_tokens()
