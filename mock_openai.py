import asyncio

class MockEmbeddings:
    async def create(self, model: str, input: list):
        class MockEmbeddingData:
            def __init__(self, embedding):
                self.embedding = embedding
        
        class MockResponse:
            def __init__(self, data):
                self.data = data
                
        # 3072 dimensions for text-embedding-3-large
        import random
        return MockResponse([MockEmbeddingData([random.random() for _ in range(3072)]) for _ in input])

class MockChatCompletions:
    async def create(self, model: str, messages: list, response_format: dict = None, temperature: float = 0, max_tokens: int = 300):
        class MockMessage:
            def __init__(self, content):
                self.content = content
                
        class MockChoice:
            def __init__(self, message):
                self.message = message
                
        class MockResponse:
            def __init__(self, choices):
                self.choices = choices
                
        prompt = messages[-1][\"content\"] if messages else \"\"
        
        # Determine what we are mocking based on prompt
        if \"produce a JSON architecture map\" in prompt:
            content = '''
            {
              \"tech_stack\": [\"Python\", \"JavaScript\", \"HTML\", \"CSS\"],
              \"entry_points\": [\"server.py\", \"index.html\"],
              \"components\": {\"server\": \"FastAPI backend orchestrator\", \"UI\": \"Frontend dashboard\"},
              \"data_flows\": [\"Client -> FastAPI -> LangGraph -> Pinecone/OpenAI\"],
              \"external_services\": [\"OpenAI\", \"Pinecone\", \"GitHub API\"],
              \"security_surface\": [\"API endpoints\", \"WebSocket streaming\", \"File parsing\"]
            }
            '''
        elif \"Evaluate this potential vulnerability\" in prompt:
            content = '''
            {
              \"is_vulnerability\": true,
              \"confirmed_type\": \"Auto-detected Security Issue\",
              \"severity\": \"HIGH\",
              \"explanation\": \"This pattern matched a known insecure coding practice requiring strict validation.\",
              \"cwe\": \"CWE-1337\"
            }
            '''
        elif \"Fix this confirmed vulnerability\" in prompt:
            import re
            match = re.search(r\"Line \\d+: (.+)\", prompt)
            original_code = match.group(1) if match else \"vulnerable_code()\"
            content = f'''
            {{
              \"patched_line\": \"# [SECURE] {original_code.strip()}\",
              \"explanation\": \"Applied a secure wrapper to mitigate the risk.\",
              \"diff_summary\": \"Replaced vulnerable execution with safe wrapper.\",
              \"imports_needed\": []
            }}
            '''
        else:
            content = \"{}\"
            
        await asyncio.sleep(1) # Simulate network delay
        return MockResponse([MockChoice(MockMessage(content))])

class AsyncOpenAI:
    def __init__(self, api_key: str = None):
        self.embeddings = MockEmbeddings()
        class MockChat:
            def __init__(self):
                self.completions = MockChatCompletions()
        self.chat = MockChat()
