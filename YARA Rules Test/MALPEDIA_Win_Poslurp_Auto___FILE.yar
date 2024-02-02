rule MALPEDIA_Win_Poslurp_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7a8f0443-88b1-5a4f-a35b-b7bc9acf8924"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poslurp"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.poslurp_auto.yar#L1-L113"
		license_url = "N/A"
		logic_hash = "95156f0f62f3b9458f6ba6ac285abaa70aca50d75127c0a8cc32d91b8191c0ea"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 0f87fd000000 668378203d 0f85f2000000 498bce }
		$sequence_1 = { cc 33c9 ff15???????? cc 488bac2440010000 }
		$sequence_2 = { 488bf5 498bfc f3a4 498bcc e8???????? }
		$sequence_3 = { ff15???????? 4c8be8 4885c0 0f84c2000000 4863453c }
		$sequence_4 = { 488d15a9100000 41b93f000f00 4533c0 48c7c102000080 }
		$sequence_5 = { 418bc1 41ffc0 486bc022 4803c2 48ffc2 }
		$sequence_6 = { 0f8301010000 418bd6 498bcf 8bfb 412bd7 }
		$sequence_7 = { 0f84ae000000 80393d 0f85a5000000 418bd6 }
		$sequence_8 = { 418bc8 ffce 488bd5 2bcd 8bfb }
		$sequence_9 = { 488bd8 4883f8ff 0f84c8010000 448b05???????? 4889ac24a0020000 4889b424a8020000 4889bc24b0020000 }

	condition:
		7 of them and filesize <50176
}