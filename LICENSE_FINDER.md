# 🧩 The SMP V6.0 License Puzzle

Welcome to the **Security Management Platform (SMP) V6.0**. 
To ensure our users aren't fools, we have locked the massive RSA-2048 master license key inside a password-protected zip file (`license_puzzle/vault.zip`). 

You must derive the password to this vault using the following cryptography puzzle. 

> [!CAUTION]
> Do not ask support for the license key. You must solve this puzzle to use the software!

---

## 🔒 Step 1: The Binary Lock
The number you need to start with is `100000000` in binary. 

**Hints:**
1. Computers read 1s and 0s. Humans read Base-10. 
2. Convert that exact binary sequence into its decimal (Base-10) equivalent number.

---

## 🔠 Step 2: The Byte Shift
Now that you have a decimal number from Step 1, it must be shifted to match the architecture bits.

**Hints:**
1. A standard computer byte consists of a specific number of bits. What is that number?
2. Multiply your decimal number from Step 1 by the number of bits in a byte.

---

## ➕ Step 3: The Vault Password
You now have a 4-digit number. We need to format it into the vault password.

**Hints:**
1. Prefix the 4-digit number with the exact word `Mega-` (make sure to include the hyphen).
2. The final format looks like: `Mega-9999`

---

### 🎯 Step 4: Extract the RSA-2048 License Key
Once you have derived your password string from Step 3, use it to unzip `license_puzzle/vault.zip`. 
Inside, you will find `huge_license.key`, which contains your massive RSA-2048 private key.

Refer back to the `USER_GUIDE.md` (Step 2) for instructions on where to place this key so the program can start!
