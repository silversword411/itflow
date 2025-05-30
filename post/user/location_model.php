<?php
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

$client_id = intval($_POST['client_id']);
$name = sanitizeInput($_POST['name']);
$description = sanitizeInput($_POST['description']);
$country = sanitizeInput($_POST['country']);
$address = sanitizeInput($_POST['address']);
$city = sanitizeInput($_POST['city']);
$state = sanitizeInput($_POST['state']);
$zip = sanitizeInput($_POST['zip']);
$phone = preg_replace("/[^0-9]/", '',$_POST['phone']);
$phone_country_code = preg_replace("/[^0-9]/", '',$_POST['phone_country_code']);
$extension = preg_replace("/[^0-9]/", '',$_POST['extension']);
$fax = preg_replace("/[^0-9]/", '',$_POST['fax']);
$fax_country_code = preg_replace("/[^0-9]/", '',$_POST['fax_country_code']);
$hours = sanitizeInput($_POST['hours']);
$notes = sanitizeInput($_POST['notes']);
$contact = intval($_POST['contact'] ?? 0);
$location_primary = intval($_POST['location_primary'] ?? 0);
