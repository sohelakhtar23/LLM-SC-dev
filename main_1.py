

from pipeline_1 import compute
from analyze_1 import revise

import os
import shutil

if __name__ == '__main__':
    compute()
    revise()

    print("\nCompression of the result in: ./output_pipeline.zip")

    # # Create a ZIP archive of the 'output' folder in a cross-platform way
    # zip_base_name = "output_pipeline"
    # zip_file = zip_base_name + ".zip"

    # # Remove existing archive if present
    # if os.path.exists(zip_file):
    #     os.remove(zip_file)

    # # Make archive: output_pipeline.zip containing the 'output' directory contents
    # shutil.make_archive(zip_base_name, "zip", "output")
