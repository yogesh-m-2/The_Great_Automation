import requests

def chatgpt_api_request(prompt):
    url = "https://api.openai.com/v1/chat/completions"
    api_key = "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"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    data = {
        "model": "tts-1",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()["choices"][0]["message"]["content"]
    else:
        print("Error:", response.text)
        return None

def main():
    while True:
        user_input = input("You: ")
        if user_input.lower() == "exit":
            print("Exiting...")
            break
        response = chatgpt_api_request(user_input)
        if response:
            print("ChatGPT:", response)

if __name__ == "__main__":
    main()
