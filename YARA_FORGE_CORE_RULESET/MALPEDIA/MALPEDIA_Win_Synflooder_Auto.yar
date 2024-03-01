rule MALPEDIA_Win_Synflooder_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "355e06d2-d319-5e82-9247-ae8f46ddbac0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.synflooder"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.synflooder_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "95bdce90d0fd23dc18864dd54db497d62acdb308355c11b707eb697b526800c1"
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
		$sequence_0 = { ff35???????? ff15???????? 85c0 7442 8b7df4 85ff }
		$sequence_1 = { 83e61f 8d3c8520fc4000 8b07 c1e606 }
		$sequence_2 = { 750b 56 e8???????? 59 85c0 7407 }
		$sequence_3 = { e8???????? 83c408 8b542420 52 68???????? e8???????? }
		$sequence_4 = { 53 56 57 7408 33c0 40 e9???????? }
		$sequence_5 = { c7465c20b04000 83660800 33ff 47 }
		$sequence_6 = { 55 8bec 81ec98050000 a1???????? 33c5 8945fc 8d8568faffff }
		$sequence_7 = { 8bf0 89742414 83feff 7524 68???????? e8???????? 83c404 }
		$sequence_8 = { ff15???????? 83f8ff 7524 68???????? e8???????? 83c404 }
		$sequence_9 = { 33db 85db 7466 8d45f4 50 ff75f8 53 }

	condition:
		7 of them and filesize <163840
}
