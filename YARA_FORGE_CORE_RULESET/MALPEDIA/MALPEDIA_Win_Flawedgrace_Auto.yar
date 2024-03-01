rule MALPEDIA_Win_Flawedgrace_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "62521b13-13e2-5f89-b92f-7685ad3e5d40"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flawedgrace"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.flawedgrace_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "3a2e50b467b7ecb293ee257669feacddf7970c96ed36da3edcb02bab7c5dbcd0"
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
		$sequence_0 = { 894110 8b450c 89411c 8a03 884124 8b45f4 c7411800000000 }
		$sequence_1 = { c1e810 0fb6c0 330c85e0bb4500 0fb6c2 c1ea08 330c85e0b34500 334fb8 }
		$sequence_2 = { ff15???????? 8bf8 85ff 0f8493000000 8bce e8???????? 8d5704 }
		$sequence_3 = { 50 8b85c0feffff ff7004 50 e8???????? 8b55e8 }
		$sequence_4 = { c68564dcffffda c68565dcffff02 c68566dcffff48 c68567dcffff65 c68568dcffff61 c68569dcffff70 c6856adcffff52 }
		$sequence_5 = { c6857fcfffff48 c68580cfffff83 c68581cfffffec c68582cfffff20 c68583cfffff4c c68584cfffff8b c68585cfffffc8 }
		$sequence_6 = { 3355f0 33da 8955e8 330c85e0d34500 8bc2 898eb0000000 8bca }
		$sequence_7 = { c6852ee8ffff65 c6852fe8ffff6c c68530e8ffff6f c68531e8ffff63 c68532e8ffff00 c68533e8ffff00 c68534e8ffff50 }
		$sequence_8 = { 8975fc e8???????? 50 83c010 50 51 }
		$sequence_9 = { c68516e5ffff00 c68517e5ffff00 c68518e5ffff00 c68519e5ffff00 c6851ae5ffff00 c6851be5ffff00 c6851ce5ffff00 }

	condition:
		7 of them and filesize <966656
}
