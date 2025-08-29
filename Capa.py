import marimo

__generated_with = "0.15.1"
app = marimo.App(width="medium")


@app.cell
def _():
    import marimo as mo
    import os
    return mo, os


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h1>Capa</h1>""")
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md("""<h2>Get plugx RAT sample</h2>""")
    return


@app.cell
def _(os):
    os.system("git clone https://github.com/mrphrazer/obfuscation_detection.git")
    return


@app.cell
def _(os):
    os.system("unzip -P infected ./obfuscation_detection/examples/samples.zip")
    return


@app.cell
def _(os):
    os.system("wget https://github.com/mandiant/capa/raw/master/web/explorer/releases/capa-explorer-web-v1.0.0-6a2330c.zip")
    return


@app.cell
def _(os):
    os.system("unzip ./capa-explorer-web-v1.0.0-6a2330c.zip")
    return


@app.cell
def _(os):
    os.system("capa --h")
    return


@app.cell
def _(os):
    os.system("capa --os windows ./samples/plugx -j > ./capa-explorer-web/result.json")
    return


if __name__ == "__main__":
    app.run()
