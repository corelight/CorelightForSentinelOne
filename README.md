# SentinelOne Dashboards for Singularity Operations Center

## Overview
This guide will help you set up and utilize SentinelOne Dashboards, which offer powerful data insights for monitoring and analyzing your network traffic. Whether you're a security analyst, network administrator, or IT professional, these dashboards will help you easily visualize and track your network's security status.

---

## Installation and Configuration

### Parser Configuration

### Installing Parsers through Marketplace

### -- TBD --

### Installing Parsers through Github Repository

**Note: To install the parsers, follow these steps if you prefer to use the GitHub repository for installation instead of marketplace.**

For installing the parsers through github repository, please follow the below steps:

**Step 1:** In the Singularity Operations Center, go to Policy and Settings Section from the bottom left corner.

![image](https://github.com/user-attachments/assets/e2009b46-1810-47ce-87ba-26a770b5e89b)

**Step 2:** From the policy and settings sections, search for Parsers and you’ll see that in the Products Section.

![image](https://github.com/user-attachments/assets/fd85477b-90f4-4f2b-8a41-aee8958c41e7)

**Step 3:** Click on the parsers section and you will see the list of inbuilt as well as created parsers.

![image](https://github.com/user-attachments/assets/f7418727-fce8-421a-bfe3-d2e7835dbe0e)

**Step 4:** Now, for adding new parser click on Add parser button from the top right corner and you will see a prompt for adding the parser name and click on Ok which will create the parser.

![image](https://github.com/user-attachments/assets/4666912d-27fd-49de-86ab-d2361109ed7c)

![image](https://github.com/user-attachments/assets/3818b586-1d2a-4008-b320-1b56d2b9d8f9)

**Step 5:** After adding a new parser with log name head over to the parsers folder in github repo and search for that specific log file and copy the code from that file and paste it in below highlighted section.

![image](https://github.com/user-attachments/assets/bc6a4d58-0e23-4b89-9593-2a59671616a5)

**Step 6:** After adding the copied code from the github repo, click on **Save File** and the parser will be added which you can see in Parsers sections.

![image](https://github.com/user-attachments/assets/72e732a9-0013-4e8b-99ee-a5f3c4e2d056)

![image](https://github.com/user-attachments/assets/85210de1-2c97-4b8b-a586-857f9d05894c)

### Data Collection

To ingest data into SentinelOne Singularity Data Lake, follow the steps provided in the SentinelOne documentation under (Singularity Marketplace → Marketplace Ingestion Integrations → Corelight Zeek Network Security Parser Integration with SentinelOne).

**Note:** If you are installing the parsers from [GitHub repo](https://github.com/corelight/CorelightForSentinelOne/blob/main/README.md#installing-parsers-through-github-repository) make sure to update the sourcetype template as **"corelight-$LOG-dev"**

### Configure Lookup Files
For populating dashboards, we need some of the configurations files (i.e Lookup files), which we need to add.

**Step 1:** In the Singularity Operations Center, go to Policy and Settings Section from the bottom left corner.

![image](https://github.com/user-attachments/assets/4c772c40-4bb1-4bdb-9be4-59a23ae82852)

**Step 2:** From the policy and settings sections, search for Configurations files and you’ll see that in Products Section.

![image](https://github.com/user-attachments/assets/da163560-a414-4570-8d5d-ef66742f3361)

**Step 3:** Head over to configuration files and you'll see the list of configuration files.

![image](https://github.com/user-attachments/assets/47df9ea5-3062-40cb-a144-b9dd6a02434b)

**Step 4:** In that click on New File and add create all the files with the same names as mentioned in the lookups folder in github repository.

![image](https://github.com/user-attachments/assets/678fbc01-e1c9-4227-9b9f-30330d407b10)

![image](https://github.com/user-attachments/assets/eeabeb1c-2799-420e-b20f-3921386f9bea)

**Step 5:** After creating files with the same names as mentioned in github repository, also copy the lookup files content and save each file.

![image](https://github.com/user-attachments/assets/0c26c514-a836-4b84-badf-4321543267d3)

Once this is done, all the lookup files will be created.

---

## Step-by-Step Guide for Using SentinelOne Dashboards

### Step 1: Log into Singularity Operations Center

1. Open your web browser and go to the Singularity Operations Center login page.
2. Enter your login credentials (username and password).
3. Click Login to enter the platform.

### Step 2: Access the Dashboards Section

1. Once you're logged in, find the Dashboards section in the navigation menu. This section allows you to manage and view all the available dashboards.
2. Click on the Dashboards option to proceed.

   ![image](https://github.com/user-attachments/assets/b7cdc446-17f0-4018-9df1-fb787b3433f9)

### Step 3: Select Your Connection and Site

1. Choose Your Connection: In the top-left corner, you'll find a drop-down menu labeled Select Connection. Here, choose the connection that you want to monitor.
   
2. Select Your Site: Once you've selected the connection, you will see a list of sites associated with that connection. Choose the site you want to analyze.

   ![image](https://github.com/user-attachments/assets/7b437b9f-82cf-451f-bb97-282c30305c8d)

### Step 4: Navigate to the Data Lake Section

1. After selecting the site, you will be taken to the Data Lake section, which is where all the data (network traffic, events, etc.) is stored and analyzed.
   
   ![image](https://github.com/user-attachments/assets/9c3f13ca-7254-43fc-afc5-4b2dce237b1c)

2. View Existing Dashboards: Here, you will see a list of existing dashboards that are already available for analysis.

   ![image](https://github.com/user-attachments/assets/ad6359ad-1ac2-43c9-8d8b-c520b875656d)

### Step 5: Create a New Dashboard

1. Click on New Dashboard: To create a new dashboard, click on the New Dashboard button located at the top right corner of the screen.
   
   ![image](https://github.com/user-attachments/assets/e6d4879f-edb5-4361-a9e9-f43416833e2f)

2. Name Your Dashboard: A pop-up window will prompt you to enter a name for the new dashboard (e.g., "Security Posture, etc").
   
3. Click Create: Once you've named your dashboard, click Create to generate the new dashboard.

   ![image](https://github.com/user-attachments/assets/636dbf3e-a15a-44e6-96e5-c81f33fea5cc)

### Step 6: Edit the Dashboard

1. Dashboard is Empty: The new dashboard will initially be empty, which means you will need to configure it with relevant widgets and data sources.
   
   ![image](https://github.com/user-attachments/assets/7be1e007-d832-4481-89bb-6f1f3a84b841)

2. Edit JSON Configuration: To customize the dashboard, click the three dots (menu icon) at the top-right corner of the dashboard page and select Edit JSON from the dropdown menu.
   
   ![image](https://github.com/user-attachments/assets/5df4ce4f-0126-4d0d-a62b-94d7505ddff8)

3. Replace JSON Code: A window will open where you can modify the JSON configuration. Replace the existing code with the pre-provided dashboard file from the [github repository](https://github.com/corelight/CorelightForSentinelOne/tree/main/dashboards). This will populate your dashboard with the correct widgets and data sources.

   ![image](https://github.com/user-attachments/assets/d880d249-4a4a-40e2-8a5b-878ecccff0cc)

4. Save the File: After making changes, click Save File at the bottom-right corner to apply the configuration.

   ![image](https://github.com/user-attachments/assets/35a0222e-4543-467a-8e4f-fedc9a0811da)

5. Once the JSON file is saved, the dashboard will be populated and it will display a variety of charts, graphs, and data visualizations.

---
