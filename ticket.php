<?php include("config.php"); ?>
<?php include("header.php"); ?>

<?php 

if(isset($_GET['ticket_id'])){
  $ticket_id = intval($_GET['ticket_id']);

  $sql = mysqli_query($mysqli,"SELECT * FROM tickets, clients, users WHERE tickets.client_id = clients.client_id AND tickets.ticket_created_by = users.user_id AND ticket_id = $ticket_id AND tickets.company_id = $session_company_id");

  if(mysqli_num_rows($sql) == 0){
    echo "<center><h1 class='text-secondary mt-5'>Nothing to see here</h1><a class='btn btn-lg btn-secondary mt-3' href='tickets.php'><i class='fa fa-fw fa-arrow-left'></i> Go Back</a></center>";

    include("footer.php");
  
  }else{

  $row = mysqli_fetch_array($sql);
  $client_id = $row['client_id'];
  $client_name = $row['client_name'];
  $client_type = $row['client_type'];
  $client_address = $row['client_address'];
  $client_city = $row['client_city'];
  $client_state = $row['client_state'];
  $client_zip = $row['client_zip'];
  $client_email = $row['client_email'];
  $client_phone = $row['client_phone'];
  if(strlen($client_phone)>2){ 
    $client_phone = substr($row['client_phone'],0,3)."-".substr($row['client_phone'],3,3)."-".substr($row['client_phone'],6,4);
  }
  $client_website = $row['client_website'];
  $client_net_terms = $row['client_net_terms'];
  if($client_net_terms == 0){
    $client_net_terms = $config_default_net_terms;
  }
  $ticket_prefix = $row['ticket_prefix'];
  $ticket_number = $row['ticket_number'];
  $ticket_category = $row['ticket_category'];
  $ticket_subject = $row['ticket_subject'];
  $ticket_details = $row['ticket_details'];
  $ticket_priority = $row['ticket_priority'];
  $ticket_status = $row['ticket_status'];
  $ticket_created_at = $row['ticket_created_at'];
  $ticket_updated_at = $row['ticket_updated_at'];
  $ticket_closed_at = $row['ticket_closed_at'];
  $ticket_created_by = $row['ticket_created_by'];
  $name = $row['name'];

  if($ticket_status == "Open"){
    $ticket_status_display = "<span class='p-2 badge badge-primary'>$ticket_status</span>";
  }elseif($ticket_status == "Working"){
    $ticket_status_display = "<span class='p-2 badge badge-success'>$ticket_status</span>";
  }else{
    $ticket_status_display = "<span class='p-2 badge badge-secondary'>$ticket_status</span>";
  }

  if($ticket_priority == "High"){
    $ticket_priority_display = "<span class='p-2 badge badge-danger'>$ticket_priority</span>";
  }elseif($ticket_priority == "Medium"){
    $ticket_priority_display = "<span class='p-2 badge badge-warning'>$ticket_priority</span>";
  }elseif($ticket_priority == "Low"){
    $ticket_priority_display = "<span class='p-2 badge badge-info'>$ticket_priority</span>";
  }else{
    $ticket_priority_display = "-";
  }

  $contact_id = $row['contact_id'];
  if(!empty($contact_id)){
    $sql_contact = mysqli_query($mysqli,"SELECT * FROM contacts WHERE contact_id = $contact_id");
    $row = mysqli_fetch_array($sql_contact);
    $contact_name = $row['contact_name'];
    $contact_title = $row['contact_title'];
    $contact_email = $row['contact_email'];
    $contact_phone = $row['contact_phone'];
    $contact_extension = $row['contact_extension'];
    $contact_mobile = $row['contact_mobile'];
    $location_id = $row['location_id'];
    if(!empty($location_id)){
      $sql_location = mysqli_query($mysqli,"SELECT * FROM locations WHERE location_id = $location_id");
      $row = mysqli_fetch_array($sql_location);
      $location_name = $row['location_name'];
    }
  }


  $ticket_assigned_to = $row['ticket_assigned_to'];
  if(empty($ticket_assigned_to)){
    $ticket_assigned_to_display = "<span class='text-danger'>Not Assigned</span>";
  }else{
    $sql_assigned_to = mysqli_query($mysqli,"SELECT * FROM users WHERE user_id = $ticket_assigned_to");
    $row = mysqli_fetch_array($sql_assigned_to);
    $ticket_assigned_to_display = $row['name'];
  }

?>

<!-- Breadcrumbs-->
<ol class="breadcrumb">
  <li class="breadcrumb-item">
    <a href="tickets.php">Tickets</a>
  </li>
  <li class="breadcrumb-item">
    <a href="client.php?client_id=<?php echo $client_id; ?>&tab=tickets"><?php echo $client_name; ?></a>
  </li>
  <li class="breadcrumb-item active">Ticket Details</li>
</ol>

<div class="row mb-3">
  <div class="col-9">
    <h3>Ticket <?php echo "$ticket_prefix$ticket_number"; ?> <?php echo $ticket_status_display; ?></h3>
  </div>
  <div class="col-3">

    <div class="dropdown dropleft text-center">
      <button class="btn btn-secondary btn-sm float-right" type="button" id="dropdownMenuButton" data-toggle="dropdown">
        <i class="fas fa-fw fa-ellipsis-v"></i>
      </button>
      <div class="dropdown-menu" aria-labelledby="dropdownMenuButton">
        <a class="dropdown-item" href="#" data-toggle="modal" data-target="#editTicketModal<?php echo $ticket_id; ?>">Edit</a>
        <div class="dropdown-divider"></div>
        <a class="dropdown-item" href="post.php?delete_client=<?php echo $client_id; ?>">Delete</a>
      </div>
    </div>
  </div>
</div>

<div class="row">

  <div class="col-md-9">

    <div class="card mb-3">
      <div class="card-header bg-dark">
        <h6 class="float-left mt-1"><?php echo $ticket_subject; ?></h6>
      </div>
      <div class="card-body">
        <p><?php echo $ticket_details; ?></p>
      </div>
    </div>

    <form class="mb-3" action="post.php" method="post" autocomplete="off">
      <input type="hidden" name="ticket_id" value="<?php echo $ticket_id; ?>">
      <div class="form-group">
        <textarea class="form-control summernote" name="ticket_update"></textarea>
      </div>
      <div class="form-row">
        <div class="col-md-3">
          <div class="form-group">
            <div class="input-group">
              <div class="input-group-prepend">
                <span class="input-group-text"><i class="fa fa-fw fa-thermometer-half"></i></span>
              </div>
              <select class="form-control select2" name="status" required>
                <option <?php if($ticket_status == 'Open'){ echo "selected"; } ?> >Open</option>
                <option <?php if($ticket_status == 'Working'){ echo "selected"; } ?> >Working</option>
                <option <?php if($ticket_status == 'On Hold'){ echo "selected"; } ?> >On Hold</option>
                <option <?php if($ticket_status == 'Closed'){ echo "selected"; } ?> >Closed</option>
              </select>
            </div>
          </div>
        </div>

        <?php if(!empty($config_smtp_host) AND !empty($client_email)){ ?>

        <div class="col-md-2">
          <div class="form-group">
            <div class="custom-control custom-checkbox">
              <input type="checkbox" class="custom-control-input" id="customControlAutosizing" name="email_ticket_update" value="1" checked>
              <label class="custom-control-label" for="customControlAutosizing">Email update to client</label>
            </div>
          </div>
        </div>

        <?php } ?>
        
        <div class="col-md-1">
          <button type="submit" name="add_ticket_update" class="btn btn-primary"><i class="fa fa-fw fa-check"></i> Save</button>
        </div>

      </div>
    
    </form>

    <?php
    $sql = mysqli_query($mysqli,"SELECT * FROM ticket_updates WHERE ticket_id = $ticket_id AND ticket_update_archived_at IS NULL ORDER BY ticket_update_id DESC");

      while($row = mysqli_fetch_array($sql)){;
        $ticket_update_id = $row['ticket_update_id'];
        $ticket_update = $row['ticket_update'];
        $ticket_update_created_at = $row['ticket_update_created_at'];
        $ticket_update_by = $row['ticket_update_by'];

        $sql_update_by = mysqli_query($mysqli,"SELECT * FROM users WHERE user_id = $ticket_update_by");
        $row = mysqli_fetch_array($sql_update_by);
        $ticket_update_by_display = $row['name'];
    ?>

    <div class="card mb-3">
      <div class="card-body">
        <p><?php echo $ticket_update; ?></p>
      </div>
      <div class="card-footer"><i class="fa fa-fw fa-clock"></i> <?php echo $ticket_update_created_at; ?> <i class="fa fa-fw fa-user"></i> <?php echo $ticket_update_by_display; ?> 
        <a href="#" data-toggle="modal" data-target="#editTicketUpdateModal<?php echo $ticket_update_id; ?>"><i class="fas fa-fw fa-edit text-secondary"></i></a>
        <a href="post.php?archive_ticket_update=<?php echo $ticket_update_id; ?>"><i class="fas fa-fw fa-trash text-danger"></i></a>
      </div>
    </div>

    <?php
    
    include("edit_ticket_update_modal.php");
    
    }
    
    ?>
  
  </div>

  <div class="col-md-3">

    <div class="card mb-3">
      <div class="card-body">
        <div>  
          <h4 class="text-secondary">Client</h4>
          <i class="fa fa-fw fa-user text-secondary ml-1 mr-2 mb-2"></i> <?php echo $client_name; ?>
          <br>
          <?php
          if(!empty($client_email)){
          ?>
          <i class="fa fa-fw fa-envelope text-secondary ml-1 mr-2 mb-2"></i> <a href="mailto:<?php echo $client_email; ?>"><?php echo $client_email; ?></a>
          <br>
          <?php
          }
          ?>
          <?php
          if(!empty($client_phone)){
          ?>
          <i class="fa fa-fw fa-phone text-secondary ml-1 mr-2 mb-2"></i> <?php echo $client_phone; ?>
          <br>
          <?php 
          } 
          ?>
        </div>
      </div>
    </div>

    <?php if(!empty($contact_id)){ ?>

    <div class="card mb-3">
      <div class="card-body">
        <div>  
          <h4 class="text-secondary">Contact</h4>
          <i class="fa fa-fw fa-user text-secondary ml-1 mr-2 mb-2"></i> <?php echo $contact_name; ?>
          <br>
          <?php
          if(!empty($location_name)){
          ?>
          <i class="fa fa-fw fa-map-marker-alt text-secondary ml-1 mr-2 mb-2"></i> <?php echo $location_name; ?>
          <br>
          <?php
          }
          ?>
          <?php
          if(!empty($contact_email)){
          ?>
          <i class="fa fa-fw fa-envelope text-secondary ml-1 mr-2 mb-2"></i> <a href="mailto:<?php echo $client_email; ?>"><?php echo $client_email; ?></a>
          <br>
          <?php
          }
          ?>
          <?php
          if(!empty($contact_phone)){
          ?>
          <i class="fa fa-fw fa-phone text-secondary ml-1 mr-2 mb-2"></i> <?php echo $contact_phone; ?>
          <br>
          <?php 
          } 
          ?>
          <?php
          if(!empty($contact_mobile)){
          ?>
          <i class="fa fa-fw fa-mobile text-secondary ml-1 mr-2 mb-2"></i> <?php echo $contact_mobile; ?>
          <br>
          <?php 
          } 
          ?>
        </div>
      </div>
    </div>

    <?php } ?>

    <div class="card card-body mb-3"> 
      <h4 class="text-secondary">Details</h4>
      <div class="ml-1"><i class="fa fa-fw fa-thermometer-half text-secondary mr-2 mb-2"></i> <?php echo $ticket_priority_display; ?></div>
      <div class="ml-1"><i class="fa fa-fw fa-user text-secondary mr-2 mb-2"></i> <?php echo $ticket_assigned_to_display; ?></div>
      <div class="ml-1"><i class="fa fa-fw fa-clock text-secondary mr-2 mb-2"></i> <?php echo $ticket_created_at; ?></div>
    </div>

    <?php
    if($ticket_status !== "Closed"){
    ?>
      <a href="post.php?close_ticket=<?php echo $ticket_id; ?>" class="btn btn-outline-danger btn-block">Close Ticket</a>
    <?php
    }
    ?>

  </div>

</div>

<?php include("edit_ticket_modal.php"); ?>

<?php 

}

}

?>

<?php include("footer.php");
