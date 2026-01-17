import json

with open('output/benchmark_results.json', 'r') as f:
    data = json.load(f)

with open("temp/compile_messages.txt", 'w', encoding='utf-8') as f:
    f.write("=" * 80 + "\n")
    f.write(" " * 25 + " Generated Solidity files Compiler Messages\n")
    f.write("=" * 80 + "\n")

    for model_name, model_data in data.items():
        f.write("\n" + "=" * 80 + "\n")
        f.write(f"MODEL: {model_name}\n")
        f.write("=" * 80 + "\n\n")

        for prompt, prompt_data in model_data.items():
            f.write(prompt + "\n")
            f.write("1st" + str(prompt_data['0']['compilation']['stderr']) + "\n")
            f.write("2nd" + str(prompt_data['1']['compilation']['stderr']) + "\n")
        f.write("\n\n")
