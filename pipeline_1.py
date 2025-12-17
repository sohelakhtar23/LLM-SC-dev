# Software Name : benchmark_pipeline_solidity_llm
# SPDX-FileCopyrightText: Copyright (c) Orange SA
# PDX-License-Identifier: GPL-3.0-only
#
# This software is distributed under the GNU GENERAL PUBLIC LICENSE
# see the "LICENSE.txt" file for more details or https://spdx.org/licenses/GPL-3.0-only.html
#
# Authors: DURAND Mathis - <mathis.durand@orange.com>
#          DASPE Etienne - <etienne.daspe@orange.com>
# Software description: This pipeline generates solidity smart contracts using LLM models.
# It compiles and analyses them, performs unit tests and produces statistics on the models
# ability to produce efficient code.

import os
import pandas as pd
import re
import requests
import json
import subprocess
import shutil
import platform
import traceback
from yaspin import yaspin
from dotenv import load_dotenv
import time

load_dotenv()

# Configure solc only on non-Windows systems where solc-select is available.
if platform.system() != "Windows":
    subprocess.run(["solc-select", "install", "0.8.25"], capture_output=True, text=True)
    subprocess.run(["solc-select", "use", "0.8.25"], capture_output=True, text=True)
else:
    print(
        "[INFO] Windows detected: skipping solc-select. "
        "Please ensure Solidity compiler 0.8.25 (solc) is installed and on your PATH."
    )

nbIteration = 1
# models = ["llama3",
#           "gemma",
#           "mistral",
#           "codegemma",
#           "codellama"]
# SOHEL edit
# models = ["deepseek-coder1.3b"]
models = [
        #   "openai/gpt-oss-20b:free",
        #   "google/gemma-3-27b-it:free",
          "mistralai/mistral-small-3.1-24b-instruct:free",
        # "meta-llama/llama-3.3-70b-instruct-free", 
        ]


def cleanRepo():
    output_dir = "output"
    extracted_tests_dir = os.path.join(output_dir, "extracted_tests")

    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    os.makedirs(extracted_tests_dir, exist_ok=True)


def initDataset(dataSetName):
    # df = pd.read_csv(dataSetName, sep=";", encoding='latin1')
    df = pd.read_csv(dataSetName, encoding="latin1")

    nbPrompts = df.shape[0]

    print("input : " + dataSetName + " (" + str(nbPrompts) + " prompts)")

    dataset = [None] * nbPrompts

    print("\t- [NAME]: [CHARS LONG] [TESTS ?]")

    extracted_tests_dir = os.path.join("output", "extracted_tests")

    for i in range(nbPrompts):
        dataset[i] = [df.iat[i, 0], df.iat[i, 1], df.iat[i, 1]]
        pattern = r"```js(.*?)```"
        res = re.findall(pattern, df.iat[i, 1], re.DOTALL)

        test_exists = False
        # write the test file if it exists in the prompt
        if res:
            content = res[0]
            js_path = os.path.join(extracted_tests_dir, df.iat[i, 0] + ".js")
            with open(js_path, 'w', encoding="utf-8") as fichier:
                fichier.write(content)
            test_exists = os.path.exists(js_path)

        print("\t- " + dataset[i][0] + ":  " + str(len(dataset[i][2])) + " " * 3 + str(test_exists))

    print("\n")

    return dataset


def initModels():
    global models

    print("models: " + str(models))

    return models


# def fetchOllama(model, prompt, temperature=0.2):
#     url = "http://localhost:11434/api/generate"
#     headers = {'Content-Type': 'application/json'}
#     payload = {
#         "model": model,
#         "prompt": prompt,
#         "stream": False,
#         "options": {
#             "temperature": temperature
#         }
#     }

#     response = requests.post(url, headers=headers, data=json.dumps(payload))

#     if response.status_code == 200:
#         return response.json()
#     else:
#         response.raise_for_status()

def fetch_openrouter(model, prompt):
    response = requests.post(
        url="https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://Sohel-app-SC.com", # Optional. Site URL for rankings on openrouter.ai.
            "X-Title": "Sohel app SC", # Optional. Site title for rankings on openrouter.ai.
        },
        data=json.dumps({
            # "model": "meta-llama/llama-3.3-70b-instruct:free",
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        })
    )
    if response.status_code == 200:
        return response.json()  
    else:
        response.raise_for_status()

def fetchLLM(model, prompt):
    res = fetch_openrouter(model, prompt)

    return {
        "response": res["choices"][0]["message"]["content"],
        "usage": res.get("usage", {})
    }

def compute():
    global nbIteration

    cleanRepo()

    dataset = initDataset("15_prompt_generation.csv")

    models_list = initModels()

    print("Iteration per model&prompt = " + str(nbIteration) + "\n")

    results = {}

    
    # For each model
    for i in range(len(models_list)):
        m = models_list[i]
        
        # check directory name is valid for windows, here model names with characters(:) not allowed in windows path
        model_dir = re.sub(r'[<>:"/\\|?*]', '_', m)
        model_output_dir = os.path.join("output", model_dir)
        if not os.path.exists(model_output_dir):
            os.makedirs(model_output_dir, exist_ok=True)

        totalDurationModel = 0
        contratsPos = 0
        promptPos = 1

        print("• " + m + " is working!")

        with yaspin(text="Processing...") as spinner:
            results[m] = {}

            # For each prompt in the dataset
            for j in range(len(dataset)):
                prompt = dataset[j]

                contract_dir = os.path.join(model_output_dir, prompt[0])
                if not os.path.exists(contract_dir):
                    os.makedirs(contract_dir, exist_ok=True)

                results[m][prompt[0]] = {}

                for k in range(nbIteration):
                    spinner.text = "Processing... "

                    # STEP 1 : generates the output

                    results[m][prompt[0]][k] = {}
                    results[m][prompt[0]][k]["compilation"] = {}
                    results[m][prompt[0]][k]["slither"] = {}
                    results[m][prompt[0]][k]["testing"] = {}

                    try:
                        time.sleep(1)  # to avoid hitting rate limits
                        res = fetchLLM(m, "Write a smart contract using Solidity for the following details. Smart Contract Task- " + prompt[1] + " Description: " + prompt[2] + "\nWrite only the solidity code.")

                        res.pop("context", None)
                        res.pop("model", None)

                        results[m][prompt[0]][k]["response"] = res["response"]

                        txt_path = os.path.join(contract_dir, f"{k}.txt")
                        with open(txt_path, 'w', encoding="utf-8") as fichier:
                            fichier.write(res["response"])

                        res.pop("response", None)

                        results[m][prompt[0]][k]["promptInfos"] = res

                        totalDurationModel += res.get('total_duration', 0)

                        # STEP 1 bis : cleaning the response -> create .sol file

                        with open(txt_path, 'r', encoding="utf-8") as file:
                            content = file.read()

                        pattern = re.compile(r'```(.*?)```', re.DOTALL)
                        matches = pattern.findall(content)

                        sol_path = os.path.join(contract_dir, f"{k}.sol")
                        with open(sol_path, 'w', encoding="utf-8") as output_file:
                            for match in matches:
                                match = match.strip()
                                lines = match.split('\n')

                                if lines and lines[0] == "solidity":
                                    lines = lines[1:]

                                if not lines:
                                    continue

                                match_clean = '\n'.join(lines)
                                first_line = lines[0]

                                # If the LLM "forgets" to generate the SPDX-License-Identifier line, we write it
                                if not first_line.startswith('// SPDX-License-Identifier:'):
                                    output_file.write('// SPDX-License-Identifier: UNLICENSED\n')

                                output_file.write(match_clean + '\n')

                        # STEP 2 : Compilation

                        result = subprocess.run(
                            ["solc", "--gas", "--bin", sol_path],
                            capture_output=True,
                            text=True
                        )
                        results[m][prompt[0]][k]["compilation"]['returnCode'] = result.returncode
                        results[m][prompt[0]][k]["compilation"]['stdout'] = result.stdout
                        results[m][prompt[0]][k]["compilation"]['stderr'] = result.stderr

                        # STEP 3 : Slither

                        result = subprocess.run(
                            ["slither", sol_path],
                            capture_output=True,
                            text=True
                        )
                        results[m][prompt[0]][k]["slither"]['returnCode'] = result.returncode
                        results[m][prompt[0]][k]["slither"]['stdout'] = result.stdout
                        results[m][prompt[0]][k]["slither"]['stderr'] = result.stderr

                        # # STEP 4 : Hardhat & testing

                        # # print("STEP4: Testing the contract...")
                        # contract_dest = os.path.join(hardhat_contracts_dir, "contract.sol")
                        # if os.path.exists(contract_dest):
                        #     os.remove(contract_dest)
                        # shutil.copy(sol_path, contract_dest)

                        # verify_src = os.path.join("output", "extracted_tests", prompt[0] + ".js")
                        # verify_dest = os.path.join(hardhat_tests_dir, "verify.js")
                        # if os.path.exists(verify_dest):
                        #     os.remove(verify_dest)
                        # shutil.copy(verify_src, verify_dest)

                        # if platform.system() == "Windows":
                        #     hardhat_command = ["npx.cmd", "hardhat", "test"]
                        # else:
                        #     hardhat_command = ["npx", "hardhat", "test"]

                        # result = subprocess.run(
                        #     hardhat_command,
                        #     cwd=hardhat_root,
                        #     capture_output=True,
                        #     text=True
                        # )
                        # results[m][prompt[0]][k]["testing"]['returnCode'] = result.returncode
                        # results[m][prompt[0]][k]["testing"]['stdout'] = result.stdout
                        # results[m][prompt[0]][k]["testing"]['stderr'] = result.stderr

                        # print(
                        #     "Process finished! contract: ["
                        #     + str(promptPos) + "/" + str(len(dataset))
                        #     + "], iteration: ["
                        #     + str(k + 1) + "/" + str(nbIteration) + "]"
                        # )
                    except Exception as e:
                        results[m][prompt[0]][k]["response"] = "error"
                        results[m][prompt[0]][k]["error"] = str(e)

                        print(
                            "Error! contract: ["
                            + str(promptPos) + "/" + str(len(dataset))
                            + "], iteration: ["
                            + str(k + 1) + "/" + str(nbIteration) + "]"
                        )
                        print(f"Exception: {e}")
                        traceback.print_exc()

                    contratsPos += 1

                promptPos += 1

            spinner.text = ""
            spinner.ok("✔ Done! " + str(contratsPos) + " outputs\n")

            print("Info :\n\ttotalDurationModel= " + str(totalDurationModel / 1e9) + " s")

    with open(os.path.join("output", "data.json"), "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)


if __name__ == '__main__':
    print("-" * 70 + "\n" + " " * 23 + " LLM bench : pipeline.py" + " " * 23 + "\n" + "-" * 70)
    compute()
    print("-" * 70)
