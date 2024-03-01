rule MALPEDIA_Win_Nitlove_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b00aecde-2bc6-57bb-930b-a202a51e31ba"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nitlove"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.nitlove_auto.yar#L1-L116"
		license_url = "N/A"
		logic_hash = "702803544b3494bdcd3ba717ae94381060ca7fe1c8bd808ab3cc38c9aa80bcd5"
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
		$sequence_0 = { 8d85c4feffff b902000080 66a5 be???????? 8d7df8 50 8d45f8 }
		$sequence_1 = { ff15???????? 85c0 74e1 837dfcff }
		$sequence_2 = { ffd7 8b75f4 8b4df8 8b859cfaffff 8b95a0faffff 83c010 }
		$sequence_3 = { 0f853d010000 6a00 56 baf3b33d04 }
		$sequence_4 = { 8945d8 8b4508 8945c0 8b450c }
		$sequence_5 = { e8???????? ffd0 bab2bb282b b9???????? }
		$sequence_6 = { ba7f22fb0e b9???????? e8???????? ffd0 }
		$sequence_7 = { 8bcb e8???????? ffd0 ff75fc ba07d457d6 8bcb }
		$sequence_8 = { 0f84aa000000 53 56 57 e8???????? e8???????? 8d45f8 }
		$sequence_9 = { ffd0 8b4dfc 6a00 8904b1 b9???????? 837dec00 }

	condition:
		7 of them and filesize <49152
}
