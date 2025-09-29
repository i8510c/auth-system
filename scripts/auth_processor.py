#!/usr/bin/env python3
import json
import hmac
import hashlib
import time
import argparse
from datetime import datetime
import os
import sys

class AuthProcessor:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.data_dir = "data"
        self.load_data()
    
    def load_data(self):
        """加载所有数据文件"""
        self.config = self.load_json("config.json")
        self.workers = self.load_json("authorized_workers.json")
        self.activations = self.load_json("activations.json")
        
        # 初始化默认数据
        if not self.config:
            self.config = {
                "system_name": "GitHub授权系统",
                "version": "1.0.0",
                "token_expire_days": 30,
                "auth_code_valid_minutes": 10,
                "max_activations": 12
            }
        
        if not self.workers:
            self.workers = {
                "workers": {
                    "4511002600001": {"name": "张三", "department": "技术部", "status": "active"},
                    "4511002600002": {"name": "李四", "department": "销售部", "status": "active"},
                    "4511002600003": {"name": "王五", "department": "市场部", "status": "active"},
                    "4511002600004": {"name": "赵六", "department": "技术部", "status": "active"},
                    "4511002600005": {"name": "钱七", "department": "销售部", "status": "active"},
                    "4511002600006": {"name": "孙八", "department": "市场部", "status": "active"},
                    "4511002600007": {"name": "周九", "department": "技术部", "status": "active"},
                    "4511002600008": {"name": "吴十", "department": "销售部", "status": "active"},
                    "4511002600009": {"name": "郑十一", "department": "市场部", "status": "active"},
                    "4511002600010": {"name": "王十二", "department": "技术部", "status": "active"},
                    "4511002600011": {"name": "李十三", "department": "销售部", "status": "active"},
                    "4511002600012": {"name": "张十四", "department": "市场部", "status": "active"}
                }
            }
        
        if not self.activations:
            self.activations = {"activations": {}, "last_updated": datetime.now().isoformat()}
    
    def load_json(self, filename):
        """加载JSON文件"""
        path = os.path.join(self.data_dir, filename)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    
    def save_json(self, filename, data):
        """保存JSON文件"""
        path = os.path.join(self.data_dir, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def save_result(self, action, result_data):
        """保存处理结果"""
        result = {
            "action": action,
            "timestamp": datetime.now().isoformat(),
            "data": result_data
        }
        self.save_json("latest_result.json", result)
    
    def generate_auth_code(self, work_id, timestamp):
        """生成授权码"""
        message = f"{work_id}{timestamp}{self.secret_key}"
        return hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()[:8].upper()
    
    def generate_token(self, work_id):
        """生成访问令牌"""
        expire_days = self.config.get("token_expire_days", 30)
        expire_time = int(time.time()) + expire_days * 24 * 3600
        
        payload = {
            'work_id': work_id,
            'expire_time': expire_time,
            'issue_time': int(time.time()),
            'token_id': hashlib.md5(f"{work_id}{time.time()}".encode()).hexdigest()[:8]
        }
        
        # 生成签名
        message = f"{work_id}{expire_time}{payload['token_id']}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        
        payload['signature'] = signature
        return payload
    
    def verify_token(self, token_data):
        """验证令牌"""
        if not token_data:
            return False, "令牌数据为空"
        
        current_time = int(time.time())
        if current_time > token_data.get('expire_time', 0):
            return False, "令牌已过期"
        
        work_id = token_data.get('work_id')
        expire_time = token_data.get('expire_time')
        token_id = token_data.get('token_id')
        
        message = f"{work_id}{expire_time}{token_id}"
        expected_signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        
        if not hmac.compare_digest(token_data.get('signature', ''), expected_signature):
            return False, "令牌签名无效"
        
        return True, "验证成功"
    
    def process_request_auth(self, work_id):
        """处理授权码请求"""
        if work_id not in self.workers.get("workers", {}):
            return {
                "success": False,
                "message": "工号未授权",
                "error_code": "WORKER_NOT_AUTHORIZED"
            }
        
        worker_info = self.workers["workers"][work_id]
        if worker_info.get("status") != "active":
            return {
                "success": False,
                "message": "工号状态异常",
                "error_code": "WORKER_INACTIVE"
            }
        
        timestamp = int(time.time())
        auth_code = self.generate_auth_code(work_id, timestamp)
        
        result = {
            "success": True,
            "timestamp": timestamp,
            "auth_code": auth_code,
            "worker_name": worker_info.get("name", ""),
            "valid_minutes": self.config.get("auth_code_valid_minutes", 10),
            "message": f"授权码有效期为{self.config.get('auth_code_valid_minutes', 10)}分钟"
        }
        
        self.save_result("request_auth", result)
        return result
    
    def process_activate(self, work_id, auth_code, timestamp, device_info):
        """处理设备激活"""
        # 验证授权码
        expected_code = self.generate_auth_code(work_id, timestamp)
        if not hmac.compare_digest(auth_code.upper(), expected_code):
            result = {
                "success": False,
                "message": "授权码无效",
                "error_code": "INVALID_AUTH_CODE"
            }
            self.save_result("activate", result)
            return result
        
        # 检查授权码是否过期
        valid_minutes = self.config.get("auth_code_valid_minutes", 10)
        if time.time() - timestamp > valid_minutes * 60:
            result = {
                "success": False,
                "message": f"授权码已过期（有效期{valid_minutes}分钟）",
                "error_code": "AUTH_CODE_EXPIRED"
            }
            self.save_result("activate", result)
            return result
        
        # 检查是否已经激活
        if work_id in self.activations.get("activations", {}):
            activation = self.activations["activations"][work_id]
            if activation.get("status") == "active":
                result = {
                    "success": False,
                    "message": "该工号已激活其他设备",
                    "error_code": "ALREADY_ACTIVATED"
                }
                self.save_result("activate", result)
                return result
        
        # 生成令牌
        token = self.generate_token(work_id)
        
        # 记录激活信息
        self.activations["activations"][work_id] = {
            "device_info": device_info,
            "activate_time": datetime.now().isoformat(),
            "last_verify": datetime.now().isoformat(),
            "token": token,
            "status": "active",
            "activate_count": self.activations["activations"].get(work_id, {}).get("activate_count", 0) + 1
        }
        
        self.activations["last_updated"] = datetime.now().isoformat()
        self.save_json("activations.json", self.activations)
        
        result = {
            "success": True,
            "token": token,
            "expire_days": self.config.get("token_expire_days", 30),
            "worker_name": self.workers["workers"][work_id].get("name", ""),
            "message": "设备激活成功"
        }
        
        self.save_result("activate", result)
        return result
    
    def process_verify(self, token_data):
        """处理令牌验证"""
        is_valid, message = self.verify_token(token_data)
        
        if not is_valid:
            result = {
                "success": False,
                "message": message,
                "error_code": "TOKEN_INVALID"
            }
            self.save_result("verify", result)
            return result
        
        work_id = token_data.get('work_id')
        
        # 更新最后验证时间
        if work_id in self.activations.get("activations", {}):
            self.activations["activations"][work_id]["last_verify"] = datetime.now().isoformat()
            self.save_json("activations.json", self.activations)
        
        result = {
            "success": True,
            "work_id": work_id,
            "worker_name": self.workers["workers"][work_id].get("name", ""),
            "message": "令牌验证成功"
        }
        
        self.save_result("verify", result)
        return result
    
    def process_status(self):
        """处理状态查询"""
        active_count = sum(1 for a in self.activations.get("activations", {}).values() 
                         if a.get("status") == "active")
        
        result = {
            "success": True,
            "system_status": {
                "total_authorized": len(self.workers.get("workers", {})),
                "active_devices": active_count,
                "max_activations": self.config.get("max_activations", 12),
                "last_updated": self.activations.get("last_updated"),
                "version": self.config.get("version", "1.0.0")
            }
        }
        
        self.save_result("status", result)
        return result

def main():
    parser = argparse.ArgumentParser(description='GitHub授权处理器')
    parser.add_argument('--action', required=True)
    parser.add_argument('--work_id')
    parser.add_argument('--auth_code')
    parser.add_argument('--timestamp', type=int)
    parser.add_argument('--device_info')
    parser.add_argument('--secret', required=True)
    
    args = parser.parse_args()
    
    processor = AuthProcessor(args.secret)
    
    try:
        if args.action == "request_auth":
            result = processor.process_request_auth(args.work_id)
        elif args.action == "activate":
            device_info = json.loads(args.device_info) if args.device_info else {}
            result = processor.process_activate(args.work_id, args.auth_code, args.timestamp, device_info)
        elif args.action == "verify":
            token_data = json.loads(args.device_info) if args.device_info else {}
            result = processor.process_verify(token_data)
        elif args.action == "status":
            result = processor.process_status()
        else:
            result = {"success": False, "message": "未知动作"}
        
        print(json.dumps(result, ensure_ascii=False))
        
    except Exception as e:
        error_result = {
            "success": False,
            "message": f"处理错误: {str(e)}",
            "error_code": "PROCESSING_ERROR"
        }
        print(json.dumps(error_result, ensure_ascii=False))
        sys.exit(1)

if __name__ == "__main__":
    main()
