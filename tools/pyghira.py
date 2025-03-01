import pyghidra
import subprocess


def decompile_and_objdump(file_path):
    decompiled_output = ""

    with pyghidra.open_program(file_path) as flat_api:
        program = flat_api.getCurrentProgram()

        from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

        decomp_api = FlatDecompilerAPI(flat_api)

        function_manager = program.getFunctionManager()
        for function in function_manager.getFunctions(True):
            decompiled_function = decomp_api.decompile(function, 30)
            decompiled_output += f"Function: {function.getName()}\n{'-'*40}\n"
            decompiled_output += decompiled_function + "\n\n"

        decomp_api.dispose()

    objdump_result = subprocess.run(
        ["objdump", "-d", file_path], capture_output=True, text=True
    )

    objdump_output = objdump_result.stdout
    return decompiled_output, objdump_output


if __name__ == "__main__":
    decompiled_path, objdump_path = decompile_and_objdump("./test/test.exe")
    print(f"Decompiled output: {decompiled_path}")
    print(f"Objdump output: {objdump_path}")
