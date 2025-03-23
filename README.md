# Malbox

Malbox is a dynamic file analyzer that performs in-depth **malware analysis** on files. It provides static and dynamic inspection capabilities, integrating multiple analysis techniques and frameworks to extract comprehensive insights.

---

## 🚀 Features

- **VirusTotal Scan**: Automatically checks files against VirusTotal's database to identify known malware signatures.
- **Decompiled Binary View**: Generates a decompiled view of the binary using **Ghidra** for advanced static analysis.
- **MITRE ATT&CK Mapping**: Identifies the capabilities of a file by mapping its behavior to the **MITRE ATT&CK** framework.
- **Dynamic Analysis**: Executes suspicious files in isolated virtual machines and collects logs from tools like **Procmon** for behavioral analysis.

---

## 🛠️ Installation

Ensure you have **Python 3.10+** and the necessary virtualization tools (e.g., VirtualBox or KVM) installed.

1. **Clone the repository**:

```bash
git clone https://github.com/basedBaba/malbox.git
cd malbox
```

2. **Set up a virtual environment (optional but recommended)**:

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:

```bash
pip install -r requirements.txt
```

4. **Configure API Keys** (for VirusTotal integration):

Create a `.env` file in the project root and add:

```bash
VIRUSTOTAL_API_KEY=your_api_key_here
```

---

## ▶️ Usage

Run the Malbox server with:

```bash
python src/main.py
```

### API Endpoints

1. **Upload and Analyze a File**

   **POST** `/api/analyze`

   **Request**:
   ```json
   {
     "file_path": "path/to/sample.exe"
   }
   ```

2. **VirusTotal Scan**

   **POST** `/api/virustotal`

   **Request**:
   ```json
   {
     "file_hash": "abc123def456"
   }
   ```

3. **Decompile with Ghidra**

   **POST** `/api/decompile`

   **Request**:
   ```json
   {
     "file_path": "path/to/binary"
   }
   ```

4. **Dynamic Analysis**

   **POST** `/api/dynamic`

   **Request**:
   ```json
   {
     "file_path": "path/to/sample.exe"
   }
   ```

Example Request with `curl`:

```bash
curl -X POST http://localhost:5000/api/analyze -H "Content-Type: application/json" -d '{"file_path": "sample.exe"}'
```

---

## 📊 Outputs

- **Static Analysis Report**: File metadata, hashes, VirusTotal results.
- **Ghidra Decompiled Code**: Decompiled source for deeper inspection.
- **MITRE ATT&CK Mapping**: Identified tactics and techniques from behavior.
- **Dynamic Logs**: Collected logs from Procmon and other monitoring tools.


---


## 🤝 Contributing

We welcome contributions! Follow these steps to contribute:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature/your-feature`.
3. Commit your changes: `git commit -m "Add new feature"`.
4. Push to the branch: `git push origin feature/your-feature`.
5. Submit a pull request.

Please ensure your code follows the existing style and includes tests where applicable.

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.

---

**Malbox** - Malware analysis On The GO!

