rule MALPEDIA_Win_Doublefantasy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "fe1fe594-5930-58a6-8152-affb40d52392"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doublefantasy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.doublefantasy_auto.yar#L1-L176"
		license_url = "N/A"
		logic_hash = "c2743e8ba6874f5905b98f01968f640324da6dd46040ee9e2e2dc712fae3b7b1"
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
		$sequence_0 = { ff75e0 e8???????? 8945c4 3d05000780 7458 3d09000c80 }
		$sequence_1 = { 770b 0fb6c0 8a80ad8c2700 eb02 32c0 84c0 7410 }
		$sequence_2 = { 8a80908c2700 eb02 b03d 884103 c3 55 }
		$sequence_3 = { 33d2 8a5001 c1ee06 83e20f c1e202 0bd6 8a92908c2700 }
		$sequence_4 = { ff750c 8b4622 03c6 50 e8???????? 83c40c be???????? }
		$sequence_5 = { 51 68???????? ff750c 8b1d???????? ffd3 83c420 ff75e0 }
		$sequence_6 = { 8a92908c2700 885101 7e1c 0fb67002 }
		$sequence_7 = { ff45f8 3c2b 720f 3c7a 770b 0fb6c0 8a80ad8c2700 }
		$sequence_8 = { 0bd6 837c241001 8a92908c2700 885101 }
		$sequence_9 = { 8a92908c2700 eb02 b23d 837c241002 885102 }
		$sequence_10 = { 85c0 7c6a 8b45e4 8b08 8d954cffffff }
		$sequence_11 = { e8???????? 8b4605 c68094a3270000 ff35???????? ff35???????? e8???????? 83c414 }
		$sequence_12 = { a5 a5 a5 66a5 6a3d 59 }
		$sequence_13 = { 68???????? 68???????? ff15???????? 83c40c 837de000 0f8660010000 }
		$sequence_14 = { ff750c ff7508 ff15???????? 8945a8 3bc3 752b }
		$sequence_15 = { 33ff eb06 56 e8???????? }

	condition:
		7 of them and filesize <172032
}