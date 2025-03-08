# 🚨 MBR Corruptor

> **Warning:** This script is highly destructive. Running it will corrupt the Master Boot Record (MBR) of all connected physical disks and force a Blue Screen of Death (BSOD) on Windows.  
> **Do not use it on any system that holds important data.**  

This project is purely educational, meant for experimentation in controlled environments. **Use at your own risk.**

---

## ❗ What This Script Does

- **Corrupts the MBR**: Modifies the first 512 bytes of all physical disks using XOR encryption (excluding the MBR signature).  
- **Triggers a BSOD**: Forces a system crash by raising a critical error.

---

## 🛠️ How It Works

1. **Retrieve Physical Drives**  
   - The script lists all connected physical drives using the Common Information Model (CIM).  

2. **Modify the MBR**  
   - Reads the first 512 bytes (MBR) from each disk.  
   - Applies XOR encryption to the first 510 bytes, leaving the last 2 bytes (MBR signature) intact.  
   - Writes the modified MBR back to the disk, making the system unbootable.  

3. **Trigger a BSOD**  
   - Adjust privileges via RtlAdjustPrivilege 
   - Forces a system crash by raising a critical error through NtRaiseHardError.

---

## ⚠️ Disclaimer

**This script is for educational purposes only.** Running it on a real system will cause irreversible damage, rendering the OS unbootable. Only use it in virtualized test environments.  

**You are fully responsible for any consequences resulting from running this script.**  

---

## 📌 License

This project is released under the [MIT License](LICENSE).

---

## 🔧 Future Improvements

- Currently, this script relies on Add-Type to compile and execute C# code to trigger the BSOD. This can be improved by using dynamic signatures, which eliminates the need for calling CSC and prevents on-disk artifacts.

---

## 🛑 Final Warning  

💀 **Running this script will permanently damage the system. Proceed only if you fully understand the risks.**  
