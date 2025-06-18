# dll_checker.py - Run this in your backend/app/core/kyber/ folder
import ctypes
import os
from pathlib import Path

def check_dll_functions():
    """Check what functions are available in the kyber.dll"""
    
    dll_path = Path(__file__).parent / "kyber.dll"
    
    if not dll_path.exists():
        print(f"❌ DLL not found at: {dll_path}")
        return
    
    print(f"✅ DLL found at: {dll_path}")
    
    try:
        # Load the DLL
        lib = ctypes.CDLL(str(dll_path))
        print("✅ DLL loaded successfully")
        
        # Common function names in Kyber implementations
        function_names = [
            "kyber_keygen",
            "kyber_keypair", 
            "crypto_kem_keypair",
            "pqcrystals_kyber512_ref_keypair",
            "kyber_encaps",
            "kyber_encrypt",
            "crypto_kem_enc",
            "pqcrystals_kyber512_ref_enc",
            "kyber_decaps", 
            "kyber_decrypt",
            "crypto_kem_dec",
            "pqcrystals_kyber512_ref_dec"
        ]
        
        available_functions = []
        
        for func_name in function_names:
            try:
                func = getattr(lib, func_name)
                available_functions.append(func_name)
                print(f"✅ Found function: {func_name}")
            except AttributeError:
                print(f"❌ Missing function: {func_name}")
        
        if available_functions:
            print(f"\n📋 Available functions: {available_functions}")
        else:
            print("\n❌ No expected functions found in DLL")
            
    except Exception as e:
        print(f"❌ Error loading DLL: {e}")

if __name__ == "__main__":
    check_dll_functions()