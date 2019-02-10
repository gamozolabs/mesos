filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".idaprobe")

with open(filename, "wb") as fd:
    fd.write(b"WOO")

idc.Exit(-5)

