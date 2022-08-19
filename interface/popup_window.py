from email import message
import tkinter as tk
from tkinter import ttk

GRID_SIZE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

def text_popup(title, text, x_grid_size = 10, y_grid_size = 10) -> None:
    """
    This function opens a new read-only text editor window. This window simply displays the given text.

    Parameters:
    -----------
        title - The text to be displayed in the window title.
        text - The text to be displayed in the new window.
        x_grid_size - The size of the horizontal grid space.
        y_grid_size - The size of the vertical grid space.

    Returns:
    --------
        Nothing
    """
    # Create new tk window.
    popup_window = tk.Tk()
    # Set window title.
    popup_window.title(title)
    # Set window to the front of others.
    popup_window.attributes("-topmost", True)
    popup_window.update()
    popup_window.attributes("-topmost", False)
    # Set sizing weights.
    popup_window.grid_rowconfigure(0, weight=1)
    popup_window.grid_columnconfigure(0, weight=1)

    # Setup window grid layout.
    row_grid_size = list(range(y_grid_size))
    column_grid_size = list(range(x_grid_size))
    popup_window.rowconfigure(row_grid_size, weight=1, minsize=60)
    popup_window.columnconfigure(column_grid_size, weight=1, minsize=70)
    # Populate upload config frame.
    text_box = tk.Text(master=popup_window, width=10, height=5)
    text_box.grid(row=0, rowspan=y_grid_size, column=0, columnspan=x_grid_size, sticky=tk.NSEW)
    # Add a Scrollbar.
    scroll=tk.Scrollbar(master=popup_window, orient='vertical', command=text_box.yview)
    scroll.grid(row=0, rowspan=y_grid_size, column=x_grid_size, sticky=tk.NS)
    # Link scroll value back to text box.
    text_box['yscrollcommand'] = scroll.set
    # Fill textbox with output text.
    text_box.insert(tk.INSERT, text)
    # Update window.
    popup_window.update()


class ListPopup():
    """
    Defines the ListPopup class. Shows a window with a dropdown list that the user can choose from.
    """
    def __init__(self):
        # Create class variables and objects.
        self.current_selection = None
        self.user_submitted_selection = None
        self.window_is_open = False

        # Create window components.
        self.popup_window = None


    def open(self, list_items, prompt="Make your selection:") -> str:
        """
        Show a popup window with a dropdown list containing the given list items. Allow the user to select one and hit OK.

        Parameters:
        -----------
            list_items - The list containing the items that the user will choose from.

        Returns:
        --------
            selection - A string with the contents/name of the selected item.
        """
        # Create new tk window.
        self.popup_window = tk.Tk()
        # Set window title.
        self.popup_window.title("List Selector")
        # Set window closing actions.
        self.popup_window.protocol("WM_DELETE_WINDOW", self.close_window)
        # Set window to the front of others.
        self.popup_window.attributes("-topmost", True)
        self.popup_window.update()
        self.popup_window.attributes("-topmost", False)
        # Set sizing weights.
        self.popup_window.grid_rowconfigure(0, weight=1)
        self.popup_window.grid_columnconfigure(0, weight=1)
        # Set toggle.
        self.window_is_open = True

        # Setup default selection.
        self.current_selection = tk.StringVar(master=self.popup_window)
        self.current_selection.set("No selection")

        # Populate window.
        select_label = tk.Label(master=self.popup_window, text=prompt)
        select_label.grid(row=0, rowspan=1, column=0, columnspan=2, sticky=tk.EW)
        drop_down = ttk.Combobox(master=self.popup_window, textvariable=self.current_selection, values=list_items)
        drop_down.grid(row=0, rowspan=1, column=2, columnspan=8, sticky=tk.EW)
        submit_button = tk.Button(master=self.popup_window,  text="Submit", foreground="black", background="white", command=self.submit_button_callback)
        submit_button.grid(row=1, column=0, columnspan=10, sticky=tk.NSEW)


        # Keep updating window until user submits something.
        while self.user_submitted_selection is None and self.window_is_open:
            # Update window.
            self.popup_window.update()

        # Close selection window if still open.
        if self.window_is_open:
            # Close window.
            self.close_window()
            # Return results.
            return self.user_submitted_selection

    def submit_button_callback(self) -> None:
        """
        This method gets called everytime the Submit button is pressed.
        
        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Check if a selection has been made.
        if self.current_selection.get() != "No selection":
            # Store the current selected value in the user submit variable.
            self.user_submitted_selection = self.current_selection.get()

    def close_window(self) -> None:
        """
        This method is called when the configure window closes.
        """
        # Set bool value.
        self.window_is_open = False
        self.popup_window.destroy()

    def get_is_window_open(self) -> bool:
        """
        Returns if the window is still open and running.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        return self.window_is_open

class MultipleListPopup():
    """
    Defines the MultipleListPopup class. Shows a window with a variable amount of dropdown lists.
    """
    def __init__(self):
        # Create class variables and objects.
        self.list_items = []
        self.current_selections = []
        self.user_submitted_selections = []
        self.row_counter = 2
        self.window_is_open = False

        # Create window componenets.
        self.popup_window = None
        self.button_frame = None
        self.list_frame = None

    def open(self, list_items, prompt="Make your selections:") -> str:
        """
        Show a popup window with a dropdown list containing the given list items. Allow the user to select one and hit OK.

        Parameters:
        -----------
            list_items - The list containing the items that the user will choose from.

        Returns:
        --------
            selection - A string with the contents/name of the selected item.
        """
        # Store list items.
        self.list_items = list_items

        # Create new tk window.
        self.popup_window = tk.Tk()
        # Set window title.
        self.popup_window.title("Variable List Selector")
        # Set window closing actions.
        self.popup_window.protocol("WM_DELETE_WINDOW", self.close_window)
        # Set window to the front of others.
        self.popup_window.attributes("-topmost", True)
        self.popup_window.update()
        self.popup_window.attributes("-topmost", False)
        # Set sizing weights.
        self.popup_window.grid_rowconfigure(GRID_SIZE, weight=1)
        self.popup_window.grid_columnconfigure(GRID_SIZE, weight=1)
        # Set toggle.
        self.window_is_open = True

        # Create frame for buttons.
        self.button_frame = tk.Frame(master=self.popup_window, relief=tk.GROOVE, borderwidth=3)
        self.button_frame.grid(row=0, rowspan=1, column=0, columnspan=10, sticky=tk.NSEW)
        self.button_frame.rowconfigure(GRID_SIZE, weight=1)
        self.button_frame.columnconfigure(GRID_SIZE, weight=1)
        # Create frame for list menus.
        self.list_frame = tk.Frame(master=self.popup_window, relief=tk.GROOVE, borderwidth=3)
        self.list_frame.grid(row=1, rowspan=9, column=0, columnspan=10, sticky=tk.NSEW)
        self.list_frame.rowconfigure(GRID_SIZE, weight=1)
        self.list_frame.columnconfigure(GRID_SIZE, weight=1)

        # Setup default selection.
        current_selection = tk.StringVar(master=self.list_frame)
        current_selection.set("No selection")
        self.current_selections.append(current_selection)

        # Populate window.
        add_button = tk.Button(master=self.button_frame,  text="Add", foreground="black", background="white", command=self.add_button_callback)
        add_button.grid(row=0, rowspan=1, column=0, columnspan=5, sticky=tk.EW)
        submit_button = tk.Button(master=self.button_frame,  text="Submit", foreground="black", background="white", command=self.submit_button_callback)
        submit_button.grid(row=0, rowspan=1, column=5, columnspan=5, sticky=tk.EW)
        select_label = tk.Label(master=self.list_frame, text=prompt)
        select_label.grid(row=0, rowspan=1, column=0, columnspan=10, sticky=tk.EW)
        drop_down = ttk.Combobox(master=self.list_frame, textvariable=current_selection, values=self.list_items)
        drop_down.grid(row=1, rowspan=1, column=0, columnspan=10, sticky=tk.EW)


        # Keep updating window until user submits something.
        while len(self.user_submitted_selections) <= 0 and self.window_is_open:
            # Update window.
            self.popup_window.update()

        # Close selection window if still open.
        if self.window_is_open:
            # Close window.
            self.close_window()
            # Return results.
            return self.user_submitted_selections

    def add_button_callback(self) -> None:
        """
        This method gets called everytime the Add button is pressed.
        
        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Create new selection variable.
        selection = tk.StringVar(self.list_frame)
        selection.set("No selection")

        # Add another selection list to the panel.
        drop_down = ttk.Combobox(master=self.list_frame, textvariable=selection, values=self.list_items)
        drop_down.grid(row=self.row_counter, rowspan=1, column=0, columnspan=10, sticky=tk.EW)
        # Add selection var to end of storage array.
        self.current_selections.append(selection)
        # Increment row counter.
        self.row_counter += 1

    def submit_button_callback(self) -> None:
        """
        This method gets called everytime the Submit button is pressed.
        
        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Loop through the current selections and print store their value in the user submit array.
        for selection in self.current_selections:
            # Check if the box selection is valid.
            if selection.get() != "No selection":
                self.user_submitted_selections.append(selection.get())

    def close_window(self) -> None:
        """
        This method is called when the configure window closes.
        """
        # Set bool value.
        self.window_is_open = False
        self.popup_window.destroy()

    def get_is_window_open(self) -> bool:
        """
        Returns if the window is still open and running.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        return self.window_is_open

class MultipleCheckboxPopup():
    """
    Defines the MultipleListPopup class. Shows a window with a variable amount of checkboxes.
    """
    def __init__(self):
        # Create class variables and objects.
        self.check_items = []
        self.check_values = []
        self.user_submit_values = []
        self.row_counter = 1
        self.window_is_open = False
        self.submitting = False

        # Create window componenets.
        self.popup_window = None
        self.button_frame = None
        self.checkbox_frame = None

    def open(self, list_items, default_check_value=False, prompt="Make your selections:") -> list:
        """
        Show a popup window with checkboxes containing the given list items. Allow the user to select each one and hit OK.

        Parameters:
        -----------
            list_items - The list containing the items that the user will choose from.
            prompt - The message to instruct the user.

        Returns:
        --------
            selections - A list containing the boolean values of the checkboxes in the same order as the given list.
        """
        # Create new tk window.
        self.popup_window = tk.Tk()
        # Set window title.
        self.popup_window.title("Checkbox List Selector")
        # Set window closing actions.
        self.popup_window.protocol("WM_DELETE_WINDOW", self.close_window)
        # Set window to the front of others.
        self.popup_window.attributes("-topmost", True)
        self.popup_window.update()
        self.popup_window.attributes("-topmost", False)
        # Set sizing weights.
        self.popup_window.grid_rowconfigure(GRID_SIZE, weight=1)
        self.popup_window.grid_columnconfigure(GRID_SIZE, weight=1)
        # Set toggle.
        self.window_is_open = True

        # Create frame for buttons.
        self.button_frame = tk.Frame(master=self.popup_window, relief=tk.GROOVE, borderwidth=3)
        self.button_frame.grid(row=0, rowspan=1, column=0, columnspan=10, sticky=tk.NSEW)
        self.button_frame.rowconfigure(GRID_SIZE, weight=1)
        self.button_frame.columnconfigure(GRID_SIZE, weight=1)
        # Create frame for list menus.
        self.list_frame = tk.Frame(master=self.popup_window, relief=tk.GROOVE, borderwidth=3)
        self.list_frame.grid(row=1, rowspan=9, column=0, columnspan=10, sticky=tk.NSEW)
        self.list_frame.rowconfigure(GRID_SIZE, weight=1)
        self.list_frame.columnconfigure(GRID_SIZE, weight=1)

        # Populate window.
        submit_button = tk.Button(master=self.button_frame,  text="Submit", foreground="black", background="white", command=self.submit_button_callback)
        submit_button.grid(row=0, rowspan=1, column=0, columnspan=len(GRID_SIZE), sticky=tk.EW)
        select_label = tk.Label(master=self.list_frame, text=prompt)
        select_label.grid(row=0, rowspan=1, column=0, columnspan=10, sticky=tk.EW)
        # Create boolean values for each list item.
        for item in list_items:
            # Create and store new boolean var to hold checkbox value.
            check_value = tk.BooleanVar(self.popup_window)
            # Set default value.
            check_value.set(default_check_value)
            self.check_values.append(check_value)
            # Create and place new checkbox.
            checkbox = tk.Checkbutton(master=self.list_frame, text=item, variable=check_value, onvalue=True, offvalue=False)
            checkbox.grid(row=self.row_counter, rowspan=1, column=0, sticky=tk.W)
            # Update counter.
            self.row_counter += 1
            # Store value.
            self.check_items.append(checkbox)


        # Keep updating window until user submits something.
        while not self.submitting and self.window_is_open:
            # Update window.
            self.popup_window.update()

        # Close selection window if still open.
        if self.window_is_open:
            # Close window.
            self.close_window()
            # Return results.
            return self.user_submit_values

    def submit_button_callback(self) -> None:
        """
        This method gets called everytime the Submit button is pressed.
        
        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Set submitting toggle/indicator.
        self.submitting = True

        # Loop through the current selections and store their value in the user submit array.
        for check_val in self.check_values:
            # Get var boolean and store.
            self.user_submit_values.append(check_val.get())

    def close_window(self) -> None:
        """
        This method is called when the configure window closes.
        """
        # Set bool value.
        self.window_is_open = False
        self.popup_window.destroy()

    def get_is_window_open(self) -> bool:
        """
        Returns if the window is still open and running.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        return self.window_is_open