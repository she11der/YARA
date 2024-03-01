rule MALPEDIA_Win_Ariabody_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "58204a37-6e57-54ad-a9ad-f1e207420b64"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ariabody"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ariabody_auto.yar#L1-L175"
		license_url = "N/A"
		logic_hash = "eeda1b828c38fb501f5c05c0fadc1525e86a5abb54edde2f591e92fd62c5dd82"
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
		$sequence_0 = { eb13 8b16 8bcf e8???????? 8906 85c0 }
		$sequence_1 = { 8bcf 0fb6c0 50 ff75fc e8???????? }
		$sequence_2 = { 7402 32c3 88040a 41 }
		$sequence_3 = { 8a01 84c0 7406 3ac3 7402 }
		$sequence_4 = { 56 8d0c30 ffd1 8bc6 5f }
		$sequence_5 = { 8bf2 56 8d55fc 03f9 e8???????? 59 85c0 }
		$sequence_6 = { 83ec50 53 57 8bd9 e8???????? 8bf8 893b }
		$sequence_7 = { ff5304 8bf8 893e eb13 8b16 8bcf }
		$sequence_8 = { 33d2 488d8c2498000000 41b800010000 41ffc7 ff9510020000 }
		$sequence_9 = { 48895c2408 57 4883ec20 4863d9 488d3da4d30000 4803db 48833cdf00 }
		$sequence_10 = { eb17 83f802 7512 488d4c2430 488d942420060000 e8???????? }
		$sequence_11 = { 33ff 488d0480 418b4cc60c 418b54c614 4903cc 458b44c610 4803d3 }
		$sequence_12 = { e8???????? 3d5595db6d 741d 4d8b7f18 }
		$sequence_13 = { 41b820000000 488d942444010000 4c8d8c2468010000 48c7402000000000 41ff96d0000000 85c0 7429 }
		$sequence_14 = { 4c89e1 4533c9 8b942464010000 41ff96c0000000 4889e0 4c89e1 41b820000000 }
		$sequence_15 = { 8b0b e8???????? 48630b 4c8d2dd59f0000 488bc1 }

	condition:
		7 of them and filesize <253952
}
