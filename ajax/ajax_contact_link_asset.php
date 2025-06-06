<?php

require_once '../includes/ajax_header.php';

$contact_id = intval($_GET['id']);

$sql = mysqli_query($mysqli, "SELECT * FROM contacts
    WHERE contact_id = $contact_id
    LIMIT 1
");

$row = mysqli_fetch_array($sql);
$contact_name = nullable_htmlentities($row['contact_name']);
$client_id = intval($row['contact_client_id']);

// Generate the HTML form content using output buffering.
ob_start();

?>

<div class="modal-header">
    <h5 class="modal-title"><i class="fa fa-fw fa-desktop mr-2"></i>Link Asset to <strong><?php echo $contact_name; ?></strong></h5>
    <button type="button" class="close text-white" data-dismiss="modal">
        <span>&times;</span>
    </button>
</div>
<form action="post.php" method="post" autocomplete="off">
    <input type="hidden" name="contact_id" value="<?php echo $contact_id; ?>">
    <div class="modal-body bg-white">

        <div class="form-group">
            <div class="input-group">
                <div class="input-group-prepend">
                    <span class="input-group-text"><i class="fa fa-fw fa-desktop"></i></span>
                </div>
                <select class="form-control select2" name="asset_id">
                    <option value="">- Select an Asset -</option>
                    <?php
                    $sql_assets_select = mysqli_query($mysqli, "
                        SELECT asset_id, asset_name
                        FROM assets
                        WHERE asset_client_id = $client_id
                        AND asset_contact_id = 0
                        AND asset_archived_at IS NULL
                        ORDER BY asset_name ASC
                    ");
                    while ($row = mysqli_fetch_array($sql_assets_select)) {
                        $asset_id = intval($row['asset_id']);
                        $asset_name = nullable_htmlentities($row['asset_name']);
                        ?>
                        <option value="<?php echo $asset_id ?>"><?php echo $asset_name; ?></option>
                        <?php
                    }
                    ?>
                </select>
            </div>
        </div>
    </div>
    <div class="modal-footer bg-white">
        <button type="submit" name="link_contact_to_asset" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Link</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fa fa-times mr-2"></i>Cancel</button>
    </div>
</form>

<?php
require_once "../includes/ajax_footer.php";
?>
