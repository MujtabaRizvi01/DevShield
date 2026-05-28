import subprocess


def run_command(cmd: str, allow_zap_exit: bool = False) -> None:
    print(f"\n===== RUNNING =====\n{cmd}\n")

    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    if process.stdout is not None:
        for line in process.stdout:
            print(line, end="")

    process.wait()

    if process.returncode != 0:
        if allow_zap_exit and process.returncode in [1, 2, 3]:
            print("ZAP finished with alerts. Continuing...")
            return
        raise Exception(f"Command failed with exit code {process.returncode}")


def cleanup_docker(container: str, image: str) -> None:
    subprocess.run(
        f"docker rm -f {container}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        f"docker rmi -f {image}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
