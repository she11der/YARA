rule MALPEDIA_Win_Bohmini_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c674d076-0d8a-5cd0-a61f-b74753074ae4"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bohmini"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.bohmini_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "924ffc111e8f5edb5600c44b643235932f72ba9b2a992fa2571ad4dc6b3c6eb8"
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
		$sequence_0 = { 896c2410 896c2414 0f86c5000000 8b7c2420 }
		$sequence_1 = { 6a00 6a00 8bca 83c11a 51 6a00 6a00 }
		$sequence_2 = { 8d542414 6a00 52 ff15???????? 85c0 }
		$sequence_3 = { ff15???????? 3bc3 a3???????? 7512 5f 5e }
		$sequence_4 = { 6800040000 50 53 ff15???????? 50 ff15???????? }
		$sequence_5 = { 4a 741a 4a 7543 e8???????? 03c6 33d2 }
		$sequence_6 = { 83c410 85c0 7507 6891130000 eb2a }
		$sequence_7 = { 8b5608 52 ffd5 40 50 }
		$sequence_8 = { 52 e8???????? 40 50 8d8424b8010000 50 }
		$sequence_9 = { 8b2d???????? 8b3e 51 6a00 ffd5 50 ffd3 }

	condition:
		7 of them and filesize <139264
}