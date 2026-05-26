# ollama_lib.py

import json
import requests

class OllamaClient:
    def __init__(self, base_url="http://localhost:11434"):
        self.base_url = base_url.rstrip('/')

    def chat(self, model, messages, tools=None):
        """
        Executes a structured chat completion inference request with modular tool-call support.

        :param model: String identifier of the target edge language model deployment.
        :param messages: List of structured message dictionary payloads (system, user, assistant).
        :param tools: Optional list of operational schemas enabling native function calling.
        :return: Dictionary representation of the JSON API execution response.
        """
        url = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": model,
            "messages": messages
        }
        
        if tools:
            payload["tools"] = tools

        headers = {"Content-Type": "application/json"}
        response = requests.post(url, data=json.dumps(payload), headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"❌ Ollama Edge Client Runtime Error: Inference pipeline request failed with status {response.status_code} - {response.text}")
