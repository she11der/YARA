rule ELASTIC_Macos_Backdoor_Kagent_64Ca1865 : FILE MEMORY
{
	meta:
		description = "Detects Macos Backdoor Kagent (MacOS.Backdoor.Kagent)"
		author = "Elastic Security"
		id = "64ca1865-0a99-49dc-b138-02b17ed47f60"
		date = "2021-11-11"
		modified = "2022-07-22"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/MacOS_Backdoor_Kagent.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
		logic_hash = "dea0a1bbe8c3065b395de50b5ffc2fbdf479ed35ce284fa33298d6ed55e960c6"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "b8086b08a019a733bee38cebdc4e25cdae9d3c238cfe7b341d8f0cd4db204d27"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$s1 = "save saveCaptureInfo"
		$s2 = "savephoto success screenCaptureInfo"
		$s3 = "no auto bbbbbaaend:%d path %s"
		$s4 = "../screencapture/screen_capture_thread.cpp"
		$s5 = "%s:%d, m_autoScreenCaptureQueue: %x"
		$s6 = "auto bbbbbaaend:%d path %s"
		$s7 = "auto aaaaaaaastartTime:%d path %s"

	condition:
		4 of them
}
