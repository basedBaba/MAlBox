import pyghidra
import subprocess
import os

def decompile_and_objdump(file_path):
    decompiled_output = ""
    
    with pyghidra.open_program(file_path) as flat_api:
        program = flat_api.getCurrentProgram()
        
        # Initialize the decompiler API
        from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
        decomp_api = FlatDecompilerAPI(flat_api)

        # Iterate through functions and print decompiled code
        function_manager = program.getFunctionManager()
        for function in function_manager.getFunctions(True):
            # print(f"Function: {function.getName()}\n{'-'*40}")
            decompiled_function = decomp_api.decompile(function, 30)
            decompiled_output += f"Function: {function.getName()}\n{'-'*40}\n"
            decompiled_output += decompiled_function + "\n\n"
        
        # Write decompiled output to file
        # with open(decompiled_file, 'w') as d_file:
        #     function_manager = program.getFunctionManager()
        #     for function in function_manager.getFunctions(True):
        #         d_file.write(f"Function: {function.getName()}\n{'-'*40}\n")
                
        #         if decompiled_function:
        #             d_file.write(decompiled_function + "\n\n")
        #         else:
        #             raise RuntimeError(f"Failed to decompile function: {function.getName()}")
        
        # Clean up the decompiler API
        decomp_api.dispose()
    
    # Run objdump and store output in file
    objdump_result = subprocess.run(
        ["objdump", "-d", file_path], 
        capture_output=True, 
        text=True
    )

    objdump_output = objdump_result.stdout
    return decompiled_output, objdump_output

# Example usage
if __name__ == "__main__":
    decompiled_path, objdump_path = decompile_and_objdump("./test/test.exe")
    print(f"Decompiled output: {decompiled_path}")
    print(f"Objdump output: {objdump_path}")
