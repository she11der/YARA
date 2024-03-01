rule MALPEDIA_Win_Unidentified_104_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e8a556d0-f78d-5a2d-8efe-d7e4f2e8c4f0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_104"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_104_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "e638b20b38ac304bb33832304ee0b9b7e6ee0e08465f3d2f98dbc6a372f89d7d"
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
		$sequence_0 = { 4c8d0d20070100 33c9 4c8d050f070100 488d1510070100 e8???????? 4885c0 }
		$sequence_1 = { 4c03e9 4d33cd 498bd9 49c1e918 48c1e328 4933d9 4803c3 }
		$sequence_2 = { 410fb6401b 4c0bc8 410fb6401a 49c1e108 4c0bc8 49c1e104 4c03c9 }
		$sequence_3 = { 48c1e128 4933c9 4c8b8c2490000000 498b8180000000 4803c1 4803e8 4c33c5 }
		$sequence_4 = { 4883fa10 0f8288000000 48ffc2 488b4dc7 488bc1 483bd7 728f }
		$sequence_5 = { 415d 415c 5f 5e 5d c3 488d5ed8 }
		$sequence_6 = { 418848fe c1e810 c1e918 418800 41884801 4d8d4004 4983e901 }
		$sequence_7 = { e8???????? 33c0 4883c420 5b c3 8bd3 488bc8 }
		$sequence_8 = { 49c1e330 4c33da 4903f3 4889b424a0000000 4833ce 488b742418 488bd1 }
		$sequence_9 = { 7230 48ffc2 488b8dc0000000 488bc1 4881fa00100000 7215 }

	condition:
		7 of them and filesize <263168
}
