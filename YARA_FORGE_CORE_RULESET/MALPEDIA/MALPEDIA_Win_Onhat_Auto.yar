rule MALPEDIA_Win_Onhat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "59032243-71bc-5ccf-a304-ec07259d2d04"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.onhat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.onhat_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "0a14e4700b595808dab4fc1d09b95f2e90fdba52a26f4d889c5bc554e4997af3"
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
		$sequence_0 = { 68???????? e8???????? 83c404 b806000080 5f 5e 5d }
		$sequence_1 = { c684242c01000048 889c242d010000 c684242e01000045 c684242f0100004e }
		$sequence_2 = { 8d7c2414 bee8030000 f3ab 8b8c2424010000 b8d34d6210 f7e1 c1ea06 }
		$sequence_3 = { 88542408 f3ab 8b8c240c200000 88542406 66ab aa 8d842410200000 }
		$sequence_4 = { 57 32d2 b9ff070000 33c0 8d7c2409 88542408 }
		$sequence_5 = { 53 ff15???????? 8bf0 3bf3 7526 }
		$sequence_6 = { 33c9 8a4c2432 8ac7 52 50 c1eb18 51 }
		$sequence_7 = { 8d7710 6a00 8d842424010000 56 50 51 e8???????? }
		$sequence_8 = { 8d54241c 55 55 52 68???????? 55 55 }
		$sequence_9 = { c644242852 c644242955 885c242a c644242b41 c644242c44 c644242d44 c644242e52 }

	condition:
		7 of them and filesize <57344
}
