// http://feliam.wordpress.com/2010/10/07/the-symbolic-maze/
// twitter.com/feliam

#include <s2e/s2e.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Maze hardcoded dimensions
#define H 7
#define W 11

// clang-format off
static char s_maze[H][W] = {
    "+-+---+---+",
    "| |     |#|",
    "| | --+ | |",
    "| |   | | |",
    "| +-- | | |",
    "|     |   |",
    "+-----+---+"
};
// clang-format on

static void draw() {
    int i, j;
    for (i = 0; i < H; i++) {
        for (j = 0; j < W; j++)
            printf("%c", s_maze[i][j]);
        printf("\n");
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    int x, y;   // Player position
    int ox, oy; // Old player position
    int i = 0;  // Iteration number

    // Initial position
    x = 1;
    y = 1;
    s_maze[y][x] = 'X';

    // Print some info
    printf("Maze dimensions: %dx%d\n", W, H);
    printf("Player pos: %dx%d\n", x, y);
    printf("Iteration no. %d\n", i);
    printf("Program the player moves with a sequence of 'w', 's', 'a' and 'd'\n");
    printf("Try to reach the price(#)!\n");

    // Draw the maze
    draw();

    // Read the directions 'program' to execute...
    // read(0,program,ITERS);

    // Iterate and run 'program'
    int max = 100;
    for (int j = 0; j < max; ++j) {
        char c = 'd';
        s2e_make_symbolic(&c, sizeof(c), "c");

        // Save old player position
        ox = x;
        oy = y;
        int do_break = 0;

        // Experimenting with S2E's state merging
        // s2e_merge_group_begin();

        // Move player position depending on the actual command
        switch (c) {
            case 'w':
                y--;
                break;
            case 's':
                y++;
                break;
            case 'a':
                x--;
                break;
            case 'd':
                x++;
                break;
            default:
                do_break = 1;
                break;
        }

        // s2e_merge_group_end();

        if (do_break) {
            printf("Wrong command!(only w,s,a,d accepted!)\n");
            printf("You lose!\n");
            exit(-1);
        }

        // If hit the price, You Win!!
        if (s_maze[y][x] == '#') {
            s2e_printf("You win!\n");
            exit(1);
        }

        // If something is wrong do not advance
        if (s_maze[y][x] != ' ' && !((y == 2 && s_maze[y][x] == '|' && x > 0 && x < W))) {
            x = ox;
            y = oy;
        }

        // Print new maze state and info...
        // s2e_printf("Player pos: %dx%d\n", x, y);
        // s2e_printf("Iteration no. %d. Action: %c. %s\n",i,c,((ox==x && oy==y)?"Blocked!":""));

        // If crashed to a wall! Exit, you lose
        if (ox == x && oy == y) {
            s2e_message("You lose\n");
            exit(-2);
        }

        // put the player on the maze...
        s_maze[y][x] = 'X';
        draw();
    }

    s2e_message("You lose\n");
}
