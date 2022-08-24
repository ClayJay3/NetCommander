from tkinter import *

from tkinter import ttk



root = Tk()

root.title('Full Window Scrolling X Y Scrollbar Example')

root.geometry("1350x400")



# Create A Main frame

main_frame = Frame(root)

main_frame.pack(fill=BOTH,expand=1)



# Create Frame for X Scrollbar

sec = Frame(main_frame)

sec.pack(fill=X,side=BOTTOM)



# Create A Canvas

my_canvas = Canvas(main_frame)

my_canvas.pack(side=LEFT,fill=BOTH,expand=1)



# Add A Scrollbars to Canvas

x_scrollbar = ttk.Scrollbar(sec,orient=HORIZONTAL,command=my_canvas.xview)

x_scrollbar.pack(side=BOTTOM,fill=X)

y_scrollbar = ttk.Scrollbar(main_frame,orient=VERTICAL,command=my_canvas.yview)
y_scrollbar.pack(side=RIGHT,fill=Y)



# Configure the canvas

my_canvas.configure(xscrollcommand=x_scrollbar.set)

my_canvas.configure(yscrollcommand=y_scrollbar.set)

my_canvas.bind("<Configure>",lambda e: my_canvas.config(scrollregion= my_canvas.bbox(ALL))) 



# Create Another Frame INSIDE the Canvas

second_frame = Frame(my_canvas)



# Add that New Frame a Window In The Canvas

my_canvas.create_window((0,0),window= second_frame, anchor="nw")





for thing in range(100):

    Button(second_frame ,text=f"Button  {thing}").grid(row=5,column=thing,pady=10,padx=10)



for thing in range(100):

    Button(second_frame ,text=f"Button  {thing}").grid(row=thing,column=5,pady=10,padx=10)



root.mainloop()