rule MALPEDIA_Win_Ransoc_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "961c0c93-e6c6-5111-8367-8742ed436406"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ransoc"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ransoc_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "2d366ed2132c1270c1bab4c471d75e367a89089f653123f697fac204fd95b124"
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
		$sequence_0 = { 8b573c 50 57 ffd2 ff4e3c 8b462c 8b4e3c }
		$sequence_1 = { 8bf0 8b5630 57 8d7e30 }
		$sequence_2 = { 894240 8b5040 895140 3bd7 741e }
		$sequence_3 = { 89703c 8b5134 895030 3bd7 7406 8b5134 }
		$sequence_4 = { 85c0 75f2 8b7140 85f6 758b 68???????? }
		$sequence_5 = { 740f 83f907 740a 83f906 }
		$sequence_6 = { 89462c a820 7406 8b4604 014804 8b462c a900080000 }
		$sequence_7 = { 895148 8b4830 85c9 7406 8b5034 895134 8b4834 }
		$sequence_8 = { 83c408 c3 6a00 6a01 55 }
		$sequence_9 = { 8b56e4 89542414 8d5c2410 891a 89442410 8b5004 8956e4 }

	condition:
		7 of them and filesize <958464
}
