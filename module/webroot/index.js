import { exec, spawn } from './kernelsu.js';

const BASE = "/data/adb/modules/testkey-signer"

let active_slot_json;
let inactive_slot_json;

window.onload = async () => {
    await exec(`chmod 700 ${BASE}/testkey-signer`);

    active_slot_json = JSON.parse((await exec(`${BASE}/testkey-signer verify-device --json`)).stdout);
    inactive_slot_json = JSON.parse((await exec(`${BASE}/testkey-signer verify-device --json --inactive-slot`)).stdout);
    console.log(active_slot_json);
    console.log(inactive_slot_json);

    update();
}

function update() {
    function ok_ng(verdict) {
        return verdict ? "OK" : "NG";
    }
    if (!active_slot_json.partition_results.vbmeta.is_testkey) {
        document.getElementById("signing-status").innerHTML = "<span style='color: red'>Unsupported device. This device is not signed by testkey.</span>" + "<br>";
    } else {
        document.getElementById("signing-status").innerHTML = `Current active slot: ${active_slot_json.slot_suffix}` + "<br>";
        document.getElementById("signing-status").innerHTML += `Active Slot: <span style="color: ${active_slot_json.all_ok ? 'green' : 'red'}">${ok_ng(active_slot_json.all_ok)}</span>` + "<br>";
        document.getElementById("signing-status").innerHTML += `Inactive Slot: <span style="color: ${inactive_slot_json.all_ok ? 'green' : 'red'}">${ok_ng(inactive_slot_json.all_ok)}</span>` + "<br>";
        if (active_slot_json.all_ok && inactive_slot_json.all_ok) {
            document.getElementById("signing-status").innerHTML += "<span style='color: green'>All slots are signed. No need for re-sign.</span>" + "<br>";
        }
    }
}

async function run(args) {
    const signer = spawn(`${BASE}/testkey-signer`, args);

    let promise = new Promise((resolve, reject) => {
        let result = "";
        signer.stdout.on('data', (data) => {
            result += data;
            data = data.replaceAll("\n", "<br>");
            document.getElementById("result").innerHTML += data + "<br>";
            console.log(`stdout: ${data}`);
        });

        signer.stderr.on('data', (data) => {
            data = data.replaceAll("\n", "<br>");
            document.getElementById("log").innerHTML += data + "<br>";
            console.log(`stderr: ${data}`);
        });

        signer.on('exit', (code) => {
            document.getElementById("log").innerHTML += `child process exited with code ${code}` + "<br>";
            console.log(`child process exited with code ${code}`);
            resolve(result);
        });
    });
}

document.getElementById("verify-current-slot").addEventListener("click", async () => {
    document.getElementById("result").innerHTML = "";
    document.getElementById("log").innerHTML = "";

    active_slot_json = await run(['verify-device', '--json']);
    update();
});

document.getElementById("verify-inactive-slot").addEventListener("click", async () => {
    document.getElementById("result").innerHTML = "";
    document.getElementById("log").innerHTML = "";

    inactive_slot_json = await run(['verify-device', '--json', '--inactive-slot']);
    update();
});

document.getElementById("patch-current-slot").addEventListener("click", () => {
    document.getElementById("result").innerHTML = "";
    document.getElementById("log").innerHTML = "";

    run(['patch-device', '--json', '--dry-run']);
});

document.getElementById("patch-inactive-slot").addEventListener("click", () => {
    document.getElementById("result").innerHTML = "";
    document.getElementById("log").innerHTML = "";

    run(['patch-device', '--json', '--inactive-slot', '--dry-run']);
});