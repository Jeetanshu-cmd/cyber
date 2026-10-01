import os
import sys

def test_folders_exist():
    expected_folders = [
        'ml', 'ml/artifacts', 'capture', 'api', 'api/routes', 'api/tests', 'dashboard', 'data', 'docs'
    ]
    all_exist = True
    for folder in expected_folders:
        if not os.path.isdir(folder):
            print(f"FAIL: Folder '{folder}' does not exist.")
            all_exist = False
        else:
            print(f"PASS: Folder '{folder}' exists.")
    return all_exist

def test_requirements_importable():
    packages = [
        'fastapi', 'uvicorn', 'pydantic', 'sqlalchemy', 'pandas', 'sklearn', 'joblib', 'pytest', 'httpx'
    ]
    all_importable = True
    for pkg in packages:
        try:
            __import__(pkg)
            print(f"PASS: Package '{pkg}' imported successfully.")
        except ImportError:
            print(f"FAIL: Package '{pkg}' could not be imported.")
            all_importable = False
    return all_importable

def test_agents_md():
    if not os.path.isfile('AGENTS.md'):
        print("FAIL: AGENTS.md does not exist.")
        return False
    if os.path.getsize('AGENTS.md') == 0:
        print("FAIL: AGENTS.md is empty.")
        return False
    print("PASS: AGENTS.md exists and is not empty.")
    return True

if __name__ == '__main__':
    print("Running setup tests...")
    f_ok = test_folders_exist()
    p_ok = test_requirements_importable()
    a_ok = test_agents_md()
    if f_ok and p_ok and a_ok:
        print("All setup tests passed successfully.")
        sys.exit(0)
    else:
        print("Some setup tests failed.")
        sys.exit(1)
