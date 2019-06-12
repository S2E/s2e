// http://feliam.wordpress.com/2010/10/07/the-symbolic-maze/ ‎
// twitter.com/feliam

#include <s2e/s2e.h>

#include <string.h>

/// Maze dimensions
#define H 7
#define W 11

typedef char line_t[W];

/// Maze map
// clang-format off
static line_t s_maze[H] = {
    "+-+---+---+",
    "| |     |#|",
    "| | --+ | |",
    "| |   | | |",
    "| +-- | | |",
    "|     |   |",
    "+-----+---+"
};
// clang-format on

static void draw(line_t *maze) {
    int i, j;
    for (i = 0; i < H; i++) {
        char line[W + 1];

        for (j = 0; j < W; j++)
            line[j] = maze[i][j];
        line[W] = 0;
        s2e_message(line);
    }
    s2e_message("");
}

void test_maze(void) {
    // We must copy on the stack because
    // global variables are in ROM and can't be modified.
    line_t maze[H];
    memcpy(maze, s_maze, sizeof(maze));

    int won = 0;
    int x, y;   // Player position
    int ox, oy; // Old player position
    int i = 0;  // Iteration number

    // Initial position
    x = 1;
    y = 1;
    maze[y][x] = 'X';

    // Draw the maze
    draw(maze);

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
            s2e_message("Wrong command (only w,s,a,d accepted)\n");
            won = 0;
            break;
        }

        // If hit the price, You Win!!
        if (maze[y][x] == '#') {
            won = 1;
            break;
        }

        // If something is wrong do not advance
        if (maze[y][x] != ' ' && !((y == 2 && maze[y][x] == '|' && x > 0 && x < W))) {
            x = ox;
            y = oy;
        }

        // If crashed to a wall! Exit, you loose
        if (ox == x && oy == y) {
            won = 0;
            break;
        }

        // put the player on the maze...
        maze[y][x] = 'X';

        // draw it
        draw(maze);

        // increment iteration
        i++;
    }

    draw(maze);

    if (won) {
        s2e_message("You won!\n");
    } else {
        s2e_message("You lost\n");
    }
}
