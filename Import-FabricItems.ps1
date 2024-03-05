Function Import-FabricItems {
  <#
  .SYNOPSIS
      Imports items using the Power BI Project format (PBIP) into a Fabric workspace from a specified file system source.

  .PARAMETER fileOverrides
      This parameter let's you override a PBIP file without altering the local file.

  .PARAMETER whatIf
      This parameter avoids running the deployment Fabric APIs, only outputting payloads to console
  #>
  [CmdletBinding()]
  param
  (
      [string]$path = '.\pbipOutput'
      ,
      [string]$workspaceId
      ,
      [string[]]$filter = $null
      ,
      [hashtable]$fileOverrides
      ,
      [bool]$whatIf = $false
      ,
      [bool]$tmdlToTsdl = $false
  )

  # All .pbir and .pbidataset objects
  $itemsInFolder = Get-ChildItem  -Path $path -recurse -include *.pbir, *.pbidataset
  if ($filter) {
      $itemsInFolder = $itemsInFolder | ? {
          $pathFolder = $_.Directory.FullName
          $filter |? { $pathFolder -ilike $_ }
      }
  }

  if ($itemsInFolder.Count -eq 0)
  {
      Write-Host "No items found in the path '$path' (*.pbir; *.pbidataset)"
      return
  }
  # Order Items, Datasets first
  $itemsInFolder = $itemsInFolder | Select-Object  @{n="Order";e={ if ($_.Name -like "*.pbidataset") {1} else {2} }}, * | sort-object Order   

  # File Overrides processing, convert all to base64 - Its the final format of the parts for Fabric APIs
  $fileOverridesEncoded = @()
  if ($fileOverrides) {
      foreach ($fileOverride in $fileOverrides.GetEnumerator())
      {
          $fileContent = $fileOverride.Value

          # convert to byte array
          if ($fileContent -is [string]) {
             
              # If its a valid path, read it as byte[]
              if (Test-Path $fileContent)
              {
                  $fileContent = [System.IO.File]::ReadAllBytes($fileContent)                       
              }
              else
              {
                  $fileContent = [system.Text.Encoding]::UTF8.GetBytes($fileContent)
              }
          }
          elseif (!($fileContent -is [byte[]])) {
              throw "FileOverrides value type must be string or byte[]"
          }
         
          $fileOverridesEncoded += @{Name=$fileOverride.Name; Value = $fileContent}
      }
  }

  # Get list of items in workspace
  if (!$whatIf) {
      $itemsInWorkspace = Invoke-FabricAPIRequest -Uri "workspaces/$workspaceId/items" -Method Get
      Write-Host "Existing items in the workspace: $($items.Count)"
  }

  $datasetReferences = @{}

  foreach ($itemInFolder in $itemsInFolder) {    
      # Get the parent folder, that contain .pbir and .pbidataset
      $FolderPath = $itemInFolder.Directory.FullName
      $FolderPathAbs = Resolve-Path $FolderPath
      write-host "Processing Folder: '$FolderPath'"

      # Process item.metadata.json, collecting item name and type
      $itemMetadataStr = Get-Content "$FolderPath\item.metadata.json"
      # If overwrites, replace file contents
      $fileOverrideMatch = $null
      if ($fileOverridesEncoded) {
          $fileOverrideMatch = $fileOverridesEncoded | ? { $filePath -ilike $_.Name  } | select -First 1 
      }
      if ($fileOverrideMatch) {
          Write-Host "File override '$fileName'"
          $itemMetadataStr = [System.Text.Encoding]::UTF8.GetString($fileOverrideMatch.Value)        
      }
      $itemMetadata = $itemMetadataStr | ConvertFrom-Json
      $itemType = if ($itemMetadata.type -ieq "dataset") {"SemanticModel"} else {$itemMetadata.type}
      $displayName = $itemMetadata.displayName
      Write-Output @{
          ItemType    = $itemType
          DisplayName = $displayName
      }

      # TMDL to TMSL
      $tmdlPath = $FolderPath + '\definition'
      if ((Test-Path $tmdlPath) -and ($tmdlToTsdl) ) {
          $db = [Microsoft.AnalysisServices.Tabular.TmdlSerializer]::DeserializeDatabaseFromFolder($tmdlPath)
          if ([string]::IsNullOrEmpty($db.Name)) {
              $db.Name ="Model" # handles cases where database name missing
          }
          $tmsl = [Microsoft.AnalysisServices.Tabular.JsonSerializer]::SerializeDatabase($db)
          $tmsl | Out-File "$itemPath\Model.bim"
          Get-ChildItem -Path $tmdlPath -Recurse | Remove-Item -force -recurse
          Remove-Item $tmdlPath -Force
      }

      # Get files required for the API (Exlcudes: item.*.json; cache.abf; .pbi folder)
      $files = Get-ChildItem -Path $FolderPath -Recurse -Attributes !Directory | ? {$_.Name -notlike "item.*.json" -and $_.Name -notlike "*.abf" -and $_.Directory.Name -notlike ".pbi"}
     
      $parts = $files | % {
          $fileName = $_.Name
          $filePath = $_.FullName  
          $fileContent = Get-Content -Path $filePath

          if ($filePath -like "*.pbir") {          
              #     $pbirJson = $fileContent | ConvertFrom-Json

              #     if ($pbirJson.datasetReference.byPath -and $pbirJson.datasetReference.byPath.path) {
              #         # try to swap byPath to byConnection, if its byConnection then just send original
              #         $reportDatasetPath = (Resolve-path (Join-Path $itemPath $pbirJson.datasetReference.byPath.path.Replace("/", "\"))).Path
              #         $datasetReference = $datasetReferences[$reportDatasetPath]      
                      
              #         if ($datasetReference) {
              #             $datasetName = $datasetReference.name
              #             $datasetId = $datasetReference.id
                         
              #             $fileContent = @{
              #                 "version" = "1.0"
              #                 "datasetReference" = @{         
              #                     "byConnection" =  @{
              #                     "connectionString" = $null               
              #                     "pbiServiceModelId" = $null
              #                     "pbiModelVirtualServerName" = "sobe_wowvirtualserver"
              #                     "pbiModelDatabaseName" = "$datasetId"               
              #                     "name" = "EntityDataSource"
              #                     "connectionType" = "pbiServiceXmlaStyleLive"
              #                     }
              #                 }
              #             } | ConvertTo-Json
                         
              #         }
              #         else
              #         {
              #             throw "Item API dont support byPath connection, switch the connection in the *.pbir file to 'byConnection'."
              #         }
              #     }
              # }
          }
         
          $fileContentEncoded = [system.Text.Encoding]::UTF8.GetBytes($fileContent)

          # If overwrites, replace file contents
          $fileOverrideMatch = $null
          if ($fileOverridesEncoded) {
              $fileOverrideMatch = $fileOverridesEncoded | ? { $filePath -ilike $_.Name  } | select -First 1 
          }
          if ($fileOverrideMatch) {
              Write-Host "File override '$fileName'"
              $fileContentEncoded = $fileOverrideMatch.Value          
          }
 
          # Generate part
          $partPath = $filePath.Replace($FolderPathAbs, "").TrimStart("\").Replace("\", "/")
          $fileEncodedContent = [Convert]::ToBase64String($fileContentEncoded)
         
          Write-Output @{
              Path        = $partPath
              Payload     = $fileEncodedContent
              PayloadType = "InlineBase64"
          }
      }

      # Deploy Parts
      Write-Host "Payload parts:"

      $parts | % { Write-Host "part: $($_.Path)" }

      $itemId = $null
      # Check if there is already an item with same displayName and type
      $foundItem = $itemsInWorkspace | ? { $_.type -ieq $itemType -and $_.displayName -ieq $displayName }
      if ($foundItem) {
          if ($foundItem.Count -gt 1) {
              throw "Found more than one item for displayName '$displayName'"
          }

          Write-Host "Item '$displayName' of type '$itemType' already exists." -ForegroundColor Yellow
          $itemId = $foundItem.id
      }

      # Create New Item
      if ($itemId -eq $null) {
          write-host "Creating a new item"

          $itemRequest = @{
              displayName = $displayName
              type        = $itemType   
              definition  = @{
                  Parts = $parts
              }
          } | ConvertTo-Json -Depth 3                          

          if (!$whatIf) {
              $createItemResult = Invoke-FabricAPIRequest -uri "workspaces/$workspaceId/items"  -method Post -body $itemRequest
              $itemId = $createItemResult.id
          }
          else {
              write-host $itemRequest -ForegroundColor Green
          }

          write-host "Created a new item with ID '$itemId' $([datetime]::Now.ToString("s"))" -ForegroundColor Green
      }

      # Update Item
      if ($itemId -ne $null) {
          write-host "Updating item definition"

          $itemRequest = @{
              definition = @{
                  Parts = $parts
              }                                            
          } | ConvertTo-Json -Depth 3                          
         
          if (!$whatIf) {
              Invoke-FabricAPIRequest -Uri "workspaces/$workspaceId/items/$itemId/updateDefinition" -Method Post -Body $itemRequest
          }
          else {
              write-host $itemRequest -ForegroundColor Green
          }

          write-host "Updated item with ID '$itemId' $([datetime]::Now.ToString("s"))" -ForegroundColor Green 
      }

      Write-Output @{
          "id" = $itemId
          "displayName" = $displayName
          "type" = $itemType
      }

      # Save dataset references to swap byPath to byConnection
      if ($itemType -ieq "semanticmodel") {
          $datasetReferences[$itemPath] = @{"id" = $itemId; "name" = $displayName}
      }
  }
}Function Import-FabricItems {
  <#
  .SYNOPSIS
      Imports items using the Power BI Project format (PBIP) into a Fabric workspace from a specified file system source.

  .PARAMETER fileOverrides
      This parameter let's you override a PBIP file without altering the local file.

  .PARAMETER whatIf
      This parameter avoids running the deployment Fabric APIs, only outputting payloads to console
  #>
  [CmdletBinding()]
  param
  (
      [string]$path = '.\pbipOutput'
      ,
      [string]$workspaceId
      ,
      [string[]]$filter = $null
      ,
      [hashtable]$fileOverrides
      ,
      [bool]$whatIf = $false
      ,
      [bool]$tmdlToTsdl = $false
  )

  # All .pbir and .pbidataset objects
  $itemsInFolder = Get-ChildItem  -Path $path -recurse -include *.pbir, *.pbidataset
  if ($filter) {
      $itemsInFolder = $itemsInFolder | ? {
          $pathFolder = $_.Directory.FullName
          $filter |? { $pathFolder -ilike $_ }
      }
  }

  if ($itemsInFolder.Count -eq 0)
  {
      Write-Host "No items found in the path '$path' (*.pbir; *.pbidataset)"
      return
  }
  # Order Items, Datasets first
  $itemsInFolder = $itemsInFolder | Select-Object  @{n="Order";e={ if ($_.Name -like "*.pbidataset") {1} else {2} }}, * | sort-object Order   

  # File Overrides processing, convert all to base64 - Its the final format of the parts for Fabric APIs
  $fileOverridesEncoded = @()
  if ($fileOverrides) {
      foreach ($fileOverride in $fileOverrides.GetEnumerator())
      {
          $fileContent = $fileOverride.Value

          # convert to byte array
          if ($fileContent -is [string]) {
             
              # If its a valid path, read it as byte[]
              if (Test-Path $fileContent)
              {
                  $fileContent = [System.IO.File]::ReadAllBytes($fileContent)                       
              }
              else
              {
                  $fileContent = [system.Text.Encoding]::UTF8.GetBytes($fileContent)
              }
          }
          elseif (!($fileContent -is [byte[]])) {
              throw "FileOverrides value type must be string or byte[]"
          }
         
          $fileOverridesEncoded += @{Name=$fileOverride.Name; Value = $fileContent}
      }
  }

  # Get list of items in workspace
  if (!$whatIf) {
      $itemsInWorkspace = Invoke-FabricAPIRequest -Uri "workspaces/$workspaceId/items" -Method Get
      Write-Host "Existing items in the workspace: $($items.Count)"
  }

  $datasetReferences = @{}

  foreach ($itemInFolder in $itemsInFolder) {    
      # Get the parent folder, that contain .pbir and .pbidataset
      $FolderPath = $itemInFolder.Directory.FullName
      $FolderPathAbs = Resolve-Path $FolderPath
      write-host "Processing Folder: '$FolderPath'"

      # Process item.metadata.json, collecting item name and type
      $itemMetadataStr = Get-Content "$FolderPath\item.metadata.json"
      # If overwrites, replace file contents
      $fileOverrideMatch = $null
      if ($fileOverridesEncoded) {
          $fileOverrideMatch = $fileOverridesEncoded | ? { $filePath -ilike $_.Name  } | select -First 1 
      }
      if ($fileOverrideMatch) {
          Write-Host "File override '$fileName'"
          $itemMetadataStr = [System.Text.Encoding]::UTF8.GetString($fileOverrideMatch.Value)        
      }
      $itemMetadata = $itemMetadataStr | ConvertFrom-Json
      $itemType = if ($itemMetadata.type -ieq "dataset") {"SemanticModel"} else {$itemMetadata.type}
      $displayName = $itemMetadata.displayName
      Write-Output @{
          ItemType    = $itemType
          DisplayName = $displayName
      }

      # TMDL to TMSL
      $tmdlPath = $FolderPath + '\definition'
      if ((Test-Path $tmdlPath) -and ($tmdlToTsdl) ) {
          $db = [Microsoft.AnalysisServices.Tabular.TmdlSerializer]::DeserializeDatabaseFromFolder($tmdlPath)
          if ([string]::IsNullOrEmpty($db.Name)) {
              $db.Name ="Model" # handles cases where database name missing
          }
          $tmsl = [Microsoft.AnalysisServices.Tabular.JsonSerializer]::SerializeDatabase($db)
          $tmsl | Out-File "$itemPath\Model.bim"
          Get-ChildItem -Path $tmdlPath -Recurse | Remove-Item -force -recurse
          Remove-Item $tmdlPath -Force
      }

      # Get files required for the API (Exlcudes: item.*.json; cache.abf; .pbi folder)
      $files = Get-ChildItem -Path $FolderPath -Recurse -Attributes !Directory | ? {$_.Name -notlike "item.*.json" -and $_.Name -notlike "*.abf" -and $_.Directory.Name -notlike ".pbi"}
     
      $parts = $files | % {
          $fileName = $_.Name
          $filePath = $_.FullName  
          $fileContent = Get-Content -Path $filePath

          if ($filePath -like "*.pbir") {          
              #     $pbirJson = $fileContent | ConvertFrom-Json

              #     if ($pbirJson.datasetReference.byPath -and $pbirJson.datasetReference.byPath.path) {
              #         # try to swap byPath to byConnection, if its byConnection then just send original
              #         $reportDatasetPath = (Resolve-path (Join-Path $itemPath $pbirJson.datasetReference.byPath.path.Replace("/", "\"))).Path
              #         $datasetReference = $datasetReferences[$reportDatasetPath]      
                      
              #         if ($datasetReference) {
              #             $datasetName = $datasetReference.name
              #             $datasetId = $datasetReference.id
                         
              #             $fileContent = @{
              #                 "version" = "1.0"
              #                 "datasetReference" = @{         
              #                     "byConnection" =  @{
              #                     "connectionString" = $null               
              #                     "pbiServiceModelId" = $null
              #                     "pbiModelVirtualServerName" = "sobe_wowvirtualserver"
              #                     "pbiModelDatabaseName" = "$datasetId"               
              #                     "name" = "EntityDataSource"
              #                     "connectionType" = "pbiServiceXmlaStyleLive"
              #                     }
              #                 }
              #             } | ConvertTo-Json
                         
              #         }
              #         else
              #         {
              #             throw "Item API dont support byPath connection, switch the connection in the *.pbir file to 'byConnection'."
              #         }
              #     }
              # }
          }
         
          $fileContentEncoded = [system.Text.Encoding]::UTF8.GetBytes($fileContent)

          # If overwrites, replace file contents
          $fileOverrideMatch = $null
          if ($fileOverridesEncoded) {
              $fileOverrideMatch = $fileOverridesEncoded | ? { $filePath -ilike $_.Name  } | select -First 1 
          }
          if ($fileOverrideMatch) {
              Write-Host "File override '$fileName'"
              $fileContentEncoded = $fileOverrideMatch.Value          
          }
 
          # Generate part
          $partPath = $filePath.Replace($FolderPathAbs, "").TrimStart("\").Replace("\", "/")
          $fileEncodedContent = [Convert]::ToBase64String($fileContentEncoded)
         
          Write-Output @{
              Path        = $partPath
              Payload     = $fileEncodedContent
              PayloadType = "InlineBase64"
          }
      }

      # Deploy Parts
      Write-Host "Payload parts:"

      $parts | % { Write-Host "part: $($_.Path)" }

      $itemId = $null
      # Check if there is already an item with same displayName and type
      $foundItem = $itemsInWorkspace | ? { $_.type -ieq $itemType -and $_.displayName -ieq $displayName }
      if ($foundItem) {
          if ($foundItem.Count -gt 1) {
              throw "Found more than one item for displayName '$displayName'"
          }

          Write-Host "Item '$displayName' of type '$itemType' already exists." -ForegroundColor Yellow
          $itemId = $foundItem.id
      }

      # Create New Item
      if ($itemId -eq $null) {
          write-host "Creating a new item"

          $itemRequest = @{
              displayName = $displayName
              type        = $itemType   
              definition  = @{
                  Parts = $parts
              }
          } | ConvertTo-Json -Depth 3                          

          if (!$whatIf) {
              $createItemResult = Invoke-FabricAPIRequest -uri "workspaces/$workspaceId/items"  -method Post -body $itemRequest
              $itemId = $createItemResult.id
          }
          else {
              write-host $itemRequest -ForegroundColor Green
          }

          write-host "Created a new item with ID '$itemId' $([datetime]::Now.ToString("s"))" -ForegroundColor Green
      }

      # Update Item
      if ($itemId -ne $null) {
          write-host "Updating item definition"

          $itemRequest = @{
              definition = @{
                  Parts = $parts
              }                                            
          } | ConvertTo-Json -Depth 3                          
         
          if (!$whatIf) {
              Invoke-FabricAPIRequest -Uri "workspaces/$workspaceId/items/$itemId/updateDefinition" -Method Post -Body $itemRequest
          }
          else {
              write-host $itemRequest -ForegroundColor Green
          }

          write-host "Updated item with ID '$itemId' $([datetime]::Now.ToString("s"))" -ForegroundColor Green 
      }

      Write-Output @{
          "id" = $itemId
          "displayName" = $displayName
          "type" = $itemType
      }

      # Save dataset references to swap byPath to byConnection
      if ($itemType -ieq "semanticmodel") {
          $datasetReferences[$itemPath] = @{"id" = $itemId; "name" = $displayName}
      }
  }
}
