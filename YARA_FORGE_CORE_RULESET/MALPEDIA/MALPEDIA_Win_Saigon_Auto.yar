rule MALPEDIA_Win_Saigon_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a473943a-8ea5-58ac-80e3-98de6dfb8169"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.saigon"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.saigon_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "a5d9048555d265aef66c2410783198e6f4dd9139107e5b71b76341530d3b556c"
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
		$sequence_0 = { 7508 ff15???????? 8bd8 4c8d5c2450 8bc3 498b5b20 498b6b28 }
		$sequence_1 = { 4889442440 488364243800 488364243000 4533c0 488bd3 33c9 }
		$sequence_2 = { ff15???????? 33ed 488bcb 85c0 }
		$sequence_3 = { 7459 f60301 742c 418bcf 488bd0 4903cc e8???????? }
		$sequence_4 = { 488b0d???????? 4c8bc7 33d2 8bd8 ff15???????? eb1e }
		$sequence_5 = { 4156 4157 4883ec60 4c8bea 488d50c8 4d8bf9 e8???????? }
		$sequence_6 = { ffd0 85c0 790e 8bc8 }
		$sequence_7 = { 4c8d8584020000 488d8c2460060000 448bcb 418bd6 e8???????? }
		$sequence_8 = { 33d2 8d440036 448bc0 448be0 ff15???????? }
		$sequence_9 = { 8d4f01 448bcf 4c8bc6 894c2428 33c9 33d2 }

	condition:
		7 of them and filesize <147456
}
