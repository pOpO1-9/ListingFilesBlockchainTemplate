# ListingFilesBlockchainTemplate
This is a simple graphical user interface (GUI) application built with Tkinter in Python to simulate a basic blockchain system. Here's a description of the key components and functionalities:

Blockchain Class:
Represents a blockchain and contains methods for creating the genesis block and adding new blocks.
Each block has a timestamp, data, previous hash, name, and its own hash, calculated based on these attributes.
User Registration and Login:

Users can register with a username and password, and their hashed passwords are stored in a dictionary (Blockchain.user_accounts).
Users can log in with their credentials, and the application checks if the entered password matches the stored hashed password.

GUI Elements:
Canvas: A canvas serves as the background for the GUI, with a simple line pattern drawn on it for visual appeal.
Registration and Login Forms: Entry fields for username and password, along with buttons for user registration and login.
Block Creation Section: Entry fields for block name, adding a file to a block, entering block data, and creating a new block.
Blockchain Search Section: Entry field for searching the blockchain based on data or block name, with a button to initiate the search.
Results Display: A text widget to display search results, with a typewriter effect for displaying results character by character.
Status Label: Displays status messages such as user registration success, login success, or errors.

Blockchain Operations:
Users can add files to blocks by browsing and selecting a file path.
Users can create new blocks by entering block name and data.
Users can search the blockchain based on data or block name, and the results are displayed with a typewriter effect.

Threading:
Threading is used to simulate a typewriter effect when displaying search results. This prevents the GUI from freezing while displaying results character by character.

Message Boxes:
Message boxes are used to show information or error messages, such as successful login, registration, or login failure.
Overall, this application provides a basic interface to interact with a simulated blockchain, allowing users to register, log in, add files to blocks, create new blocks, and search the blockchain. It serves as an educational example of a blockchain GUI using Tkinter in Python.
