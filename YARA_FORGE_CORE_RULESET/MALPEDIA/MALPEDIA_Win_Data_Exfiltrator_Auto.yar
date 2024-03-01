rule MALPEDIA_Win_Data_Exfiltrator_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a4e15d5b-f5a8-5629-8aa0-4b08d538c94b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.data_exfiltrator"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.data_exfiltrator_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "3310f9551fc82e6e58581f9d53ef710d168d316a9e233b611258320515dc0adb"
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
		$sequence_0 = { 488b4c2440 ff15???????? 4889442420 488b542448 }
		$sequence_1 = { e8???????? 4c8b442428 488d152c570000 488b4c2420 e8???????? 41b80a000000 }
		$sequence_2 = { 488d8c24a0000000 e8???????? 488d9424a0000000 488b8c2430010000 e8???????? 488905???????? }
		$sequence_3 = { c68424ba00000078 c68424bb00000078 c68424bc00000078 c68424bd00000078 c68424be00000000 488d8c24a0000000 }
		$sequence_4 = { 48894c2408 4883ec48 48837c246001 752b }
		$sequence_5 = { c6442420fb c6442421fc c6442422fe c6442423ff c6442424aa c64424254d }
		$sequence_6 = { c68424020100006d c684240301000000 c684240401000007 c68424050100006d c68424060100004f c684240701000072 }
		$sequence_7 = { 89442428 837c242800 7c3a 8b442448 39442428 7d30 8b442420 }
		$sequence_8 = { 7417 488b442450 488b4c2448 4803c8 488bc1 }
		$sequence_9 = { 48837c242800 7509 488d05d8250000 eb22 488d542420 488b4c2428 ff15???????? }

	condition:
		7 of them and filesize <107520
}
