import marimo

__generated_with = "0.15.1"
app = marimo.App(width="medium")


@app.cell(hide_code=True)
def _():
    import marimo as mo
    import os
    import pandas as pd
    import seaborn as sns
    import hashlib
    import math
    import csv
    import itertools
    import altair as alt
    import duckdb
    from collections import Counter
    import matplotlib.pyplot as plt
    return alt, csv, duckdb, mo, os, pd


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h1>Ghidra 11.4.2 and PyGhidra</h1>""")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h2>Downloading Firmware</h2>""")
    return


@app.cell
def _(os):
    os.system("wget https://github.com/therealsaumil/emux/raw/refs/heads/master/files/emux/firmware/AC15/squashfs-root.tar.bz2")
    os.system("wget https://github.com/therealsaumil/emux/raw/refs/heads/master/files/emux/firmware/TRI227WF/rootfs.tar.bz2")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h2>Decompressing Firmware</h2>""")
    return


@app.cell
def _(os):
    os.system("bzip2 -d ./rootfs.tar.bz2")
    os.system("bzip2 -d ./squashfs-root.tar.bz2")
    os.system("tar -xvf ./rootfs.tar")
    os.system("tar -xvf ./squashfs-root.tar")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h2>Creating Directories</h2>""")
    return


@app.cell
def _(os):
    os.system("mkdir ./AC15")
    os.system("cp ./squashfs-root/bin/httpd ./AC15/AC15_httpd")
    os.system("cp ./rootfs/usr/bin/webs ./AC15/TRI227WF_webs")
    return


@app.cell
def _():
    import pyghidra

    from operator import itemgetter

    pyghidra.start()

    import ghidra
    from ghidra.app.util.headless import HeadlessAnalyzer
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.base.project import GhidraProject
    from java.lang import String
    from ghidra.program.util import DefinedDataIterator, CyclomaticComplexity
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.exception import CancelledException
    return CancelledException, CyclomaticComplexity, itemgetter, pyghidra


@app.cell
def _():
    # Define dangerous functions
    dangerous_functions = ["system", "execve", "execle", "execvp", "execlp", "doSystemCmd"]
    return (dangerous_functions,)


@app.function
def format_high_complexity_funcs(funcs):
    """Format the top 10 high complexity functions as a string."""
    return "; ".join([f"{name}({cc})" for name, cc in funcs])


@app.cell
def _(
    CancelledException,
    CyclomaticComplexity,
    csv,
    dangerous_functions,
    itemgetter,
    pyghidra,
):
    def analyze_binary(binary_path):
        try:
            with pyghidra.open_program(binary_path) as flat_api:
                # Get program and listing
                current_program = flat_api.getCurrentProgram()
                listing = current_program.getListing()

                # Get basic program info
                files = current_program.getName()
                arches = current_program.getLanguage().toString()
                sha256 = current_program.getExecutableSHA256()
                md5 = current_program.getExecutableMD5()
                total_insn = listing.getNumInstructions()

                # Get functions and calculate metrics
                all_funcs = list(listing.getFunctions(True))
                total_cc = 0
                system_xrefs_details = []
                monitor = flat_api.getMonitor()

                # Analyze dangerous functions and their xrefs
                ref_manager = current_program.getReferenceManager()
                for func in all_funcs:
                    if func.getName() in dangerous_functions:
                        entry_point = func.getEntryPoint()
                        references = ref_manager.getReferencesTo(entry_point)
                        for xref in references:
                            ref_func = listing.getFunctionContaining(xref.getFromAddress())
                            if ref_func:
                                detail = f"{xref.getFromAddress()} ({ref_func.getName()})"
                                system_xrefs_details.append(detail)

                num_calls_in_system_xrefs = len(system_xrefs_details)

                # Calculate cyclomatic complexity metrics
                cc_calculator = CyclomaticComplexity()
                complexity_funcs = []
                for func in all_funcs:
                    try:
                        cc = cc_calculator.calculateCyclomaticComplexity(func, monitor)
                        total_cc += cc
                        # Store all functions with their complexity
                        complexity_funcs.append((func.getName(), cc))
                    except CancelledException:
                        print(
                            f"Warning: Complexity calculation cancelled for function {func.getName()}"
                        )

                num_funcs = len(all_funcs)
                average_cc = total_cc / num_funcs if num_funcs > 0 else 0

                # Sort functions by complexity and get top 10
                top_complex_funcs = sorted(
                    complexity_funcs, key=itemgetter(1), reverse=True
                )[:10]

                # Save results to CSV
                csv_file_path = "./ghidratest.csv"
                with open(csv_file_path, mode="a", newline="") as csv_file:
                    fieldnames = [
                        "File",
                        "Architecture",
                        "SHA256",
                        "MD5",
                        "Total_Instructions",
                        "Total_Functions",
                        "System_Xrefs",
                        "Total_System_Xrefs",
                        "Average_Cyclomatic_Complexity",
                        "Top_10_Complex_Functions",  # New field
                    ]
                    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

                    if csv_file.tell() == 0:
                        writer.writeheader()

                    writer.writerow(
                        {
                            "File": files,
                            "Architecture": arches,
                            "SHA256": sha256,
                            "MD5": md5,
                            "Total_Instructions": total_insn,
                            "Total_Functions": num_funcs,
                            "System_Xrefs": "; ".join(system_xrefs_details),
                            "Total_System_Xrefs": num_calls_in_system_xrefs,
                            "Average_Cyclomatic_Complexity": round(average_cc, 2),
                            "Top_10_Complex_Functions": format_high_complexity_funcs(
                                top_complex_funcs
                            ),
                        }
                    )

        except Exception as e:
            print(f"Error loading binary {binary_path}: {str(e)}. Skipping file.")
        except Exception as e:
            print(f"Error analyzing binary: {str(e)}")
            raise
    return (analyze_binary,)


@app.cell
def _(analyze_binary, os):
    def scan_directory(directory_path):
        # Scan the directory for binaries and analyze each one
        for root, _, files in os.walk(directory_path):
            for file in files:
                binary_path = os.path.join(root, file)
                if os.path.isfile(binary_path):  # Make sure it's a file
                    print(f"Analyzing binary: {binary_path}")
                    analyze_binary(binary_path)
    return (scan_directory,)


@app.cell
def _(scan_directory):
    if __name__ == "__main__":
        # Change this path to the directory you want to scan
        directory_path = "./AC15/"
        scan_directory(directory_path)
    return


@app.cell
def _(pd):
    def _():
        df = pd.read_csv("./ghidratest.csv", header=None)
        return


    _()
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h2>Naming Pandas Columns</h2>""")
    return


@app.cell
def _(df):
    df.columns = [
        "File",
        "Architecture",
        "SHA256",
        "MD5",
        "Strings",
        "Functions",
        "System_Xrefs",
        "Total_System_Xrefs",
        "Average_Cyclomatic_Complexity",
        "Top_10_Complex_Functions",
    ]
    return


@app.cell
def _(pd):
    df = pd.read_csv(
        "ghidratest.csv",
        dtype={
            "Total_Instructions": int,
            "Total_Functions": int,
            "Total_System_Xrefs": int,
            "Average_Cyclomatic_Complexity": float,
        },
    )
    return (df,)


@app.cell
def _(df):
    df.fillna("None", inplace=True)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h2>Verify the Pandas Output</h2>""")
    return


@app.cell
def _(df):
    df
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h2>Searching for Features</h2>""")
    return


@app.cell
def _(duckdb, mo):
    query1 = """
    SELECT * 
    FROM df 
    WHERE Average_Cyclomatic_Complexity > 3
    """

    sim = duckdb.query(query1).to_df()
    mo.ui.dataframe(sim)
    return


@app.cell
def _(df):
    df_sorted = df.sort_values(by="Total_System_Xrefs", ascending=False)
    return (df_sorted,)


@app.cell
def _(alt, df_sorted):
    alt.Chart(df_sorted).mark_bar().encode(
        x='File',
        y='Total_System_Xrefs'
    ).properties(
        title='Potentially Dangerous Calls To System'
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h2>Creating Charts Using Pandas Bokeh</h2>""")
    return


@app.cell
def _(alt, df):
    alt.Chart(df).mark_bar().encode(
        x='File',
        y='Average_Cyclomatic_Complexity'
    ).properties(
        title='Average Cyclomatic Complexity'
    )
    return


@app.cell
def _(pd):
    # Process the Top_10_Complex_Functions column
    def extract_func_data(func_str):
        # Split the string into individual function entries
        funcs = func_str.split("; ")

        # Extract function names and complexity scores
        names = []
        scores = []
        for func in funcs:
            if func:  # Check if the function entry is not empty
                name, score = func.strip("() ").split("(")
                names.append(name)
                scores.append(float(score))

        return pd.DataFrame({"Function_Name": names, "Complexity": scores})
    return (extract_func_data,)


@app.cell
def _(alt, df, extract_func_data):
    # Create a visualization for each binary
    for idx, row in df.iterrows():
        binary_name = row["File"]
        func_data = extract_func_data(row["Top_10_Complex_Functions"])

        # Create bar plot
        plot = alt.Chart(func_data).mark_bar().encode(
            x='Function_Name',
            y='Complexity'
        ).properties(
            title=f"Top 10 High Complexity Functions in {binary_name}"
        )
    return (plot,)


@app.cell
def _(plot):
    plot
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h2>Reference Material</h2>""")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""- 10 Minutes to Pandas: https://pandas.pydata.org/docs/user_guide/10min.html\n- Pandas Cookbook: https://pandas.pydata.org/docs/user_guide/cookbook.html#cookbook\n- Ghidra API: https://ghidra.re/ghidra_docs/api/index.html\n- PyGhidra: https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra\n- EMUX: https://github.com/therealsaumil/emux\n- Ghidra Snippets: https://github.com/HackOvert/GhidraSnippets\n- Auditing system calls for command injection vulnerabilities using Ghidra's PCode: https://youtu.be/UVNeg7Vqytc\n- cetfor/SystemCallAuditorGhidra.py: https://github.com/HackOvert/PotentiallyVulnerable/blob/main/CWE-78/SystemCallAuditorGhidra.py""")
    return


if __name__ == "__main__":
    app.run()
