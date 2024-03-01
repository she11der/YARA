rule MALPEDIA_Win_Syscon_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "10b2a70f-de71-5dcd-8008-91d876f6f351"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.syscon"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.syscon_auto.yar#L1-L166"
		license_url = "N/A"
		logic_hash = "f7cdfe4679f457a034e50dc400c88cdf6f80bb02175055d824368da084861b59"
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
		$sequence_0 = { 83e4f8 81ecdc0b0000 a1???????? 33c4 898424d80b0000 53 56 }
		$sequence_1 = { 0f84af000000 53 57 8bc6 e8???????? 83c408 }
		$sequence_2 = { 0f84d8000000 6a00 8d4dfc 51 53 }
		$sequence_3 = { ffd7 8d4c2428 51 8d942414040000 68???????? }
		$sequence_4 = { 88040f 47 897df8 8b45f4 03c6 }
		$sequence_5 = { ffd6 68???????? ffd6 5f 5e b801000000 }
		$sequence_6 = { ffd6 68???????? c745fc00000000 ffd6 }
		$sequence_7 = { 8935???????? ffd7 8d5e01 85c0 7539 a1???????? }
		$sequence_8 = { ff15???????? 488905???????? 4885c0 0f84fbf8ffff }
		$sequence_9 = { 4885c0 7486 488364242000 4c8d8d90030000 448bc3 488bd0 488bcf }
		$sequence_10 = { 80bd3006000020 418bce 7511 488d8530060000 }
		$sequence_11 = { 33d2 e8???????? 488d0da4320000 ff15???????? 488d9520040000 488d0d90320000 448bc0 }
		$sequence_12 = { 488d8d10020000 ff15???????? 488d4d90 448bc3 }
		$sequence_13 = { 488d5590 488d0daa300000 448bc0 e8???????? }
		$sequence_14 = { 488d542450 488d0dad290000 448bc0 e8???????? 488b0d???????? }
		$sequence_15 = { 488d4c2420 4c8bc6 33d2 e8???????? 488d0dc5450000 }

	condition:
		7 of them and filesize <120832
}
